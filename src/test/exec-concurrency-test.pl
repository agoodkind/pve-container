#!/usr/bin/perl -T

# Starts commands through the exec method of PVE::API2::LXC from several processes at the same
# time, as the workers of pvedaemon do, and requires every start to return a pid.
# Each process runs the production code of exec and PVE::RESTEnvironment::fork_worker. The test
# replaces the container lookup and lxc-attach, which need a node, and the process start time
# check, which fails under the emulation of the amd64 test image.

use strict;
use warnings;

use Cwd qw(abs_path);
use File::Path qw(make_path);
use File::Temp qw(tempdir);
use JSON;
use POSIX;
use Time::HiRes qw();

use lib qw(..);

use AnyEvent;

use PVE::API2::LXC;
use PVE::LXC;
use PVE::LXC::Config;
use PVE::ProcFSTools;
use PVE::RPCEnvironment;

my $PROCESS_COUNT = 4;
my $CALLS_PER_PROCESS = 15;
my $VMID = 9004;
my $TOKEN_USER = 'svc@pve!deploy';
my $POLL_SECONDS = 30;

{
    no warnings 'redefine';
    *PVE::LXC::Config::load_config = sub { return {} };
    *PVE::LXC::check_running = sub { return 1 };
    *PVE::ProcFSTools::read_proc_starttime = sub { return 1 };
}

my $fake_attach = abs_path('exec-fake-lxc-attach');
die "missing exec-fake-lxc-attach\n" if !defined($fake_attach) || $fake_attach !~ m/\A(\S+)\z/;
$fake_attach = $1;

my $bin_directory = tempdir(CLEANUP => 1);
die "unexpected temporary directory\n" if $bin_directory !~ m/\A(\S+)\z/;
$bin_directory = $1;
symlink($fake_attach, "$bin_directory/lxc-attach") or die "symlink failed: $!\n";
$ENV{PATH} = "$bin_directory:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin";
delete @ENV{qw(IFS CDPATH ENV BASH_ENV)};

# pvedaemon runs on AnyEvent, and the SIGCHLD handler of the environment then postpones the
# reaping of finished workers to the event loop.
AnyEvent::detect();

# fork_worker writes the task log below this directory, which exists on a node.
make_path('/var/log/pve/tasks');

my $exec_info = PVE::API2::LXC->map_method_by_name('exec');
my $status_info = PVE::API2::LXC->map_method_by_name('exec_status');

# One process: calls exec repeatedly, then polls every started command until it exits.
# Every second call runs with no user in the environment, the state that follows a request
# that cleared the user.
sub run_process {
    my ($write_handle) = @_;

    my $rpcenv = PVE::RPCEnvironment->init('priv');
    my @started;
    my @errors;
    for my $call (1 .. $CALLS_PER_PROCESS) {
        if ($call % 2) {
            $rpcenv->set_user($TOKEN_USER);
        } else {
            $rpcenv->set_user(undef);
        }
        my $result = eval {
            $exec_info->{code}->({ vmid => $VMID, command => ['true'], timeout => 30 });
        };
        $rpcenv->set_user(undef);
        if (my $error = $@) {
            chomp($error);
            push @errors, $error;
            next;
        }
        push @started, $result->{pid};
    }

    my $deadline = Time::HiRes::time() + $POLL_SECONDS;
    for my $pid (@started) {
        my $exited = 0;
        while (!$exited && Time::HiRes::time() < $deadline) {
            my $status = $status_info->{code}->({ vmid => $VMID, pid => $pid });
            $exited = $status->{exited};
            Time::HiRes::sleep(0.05) if !$exited;
        }
        push @errors, "command $pid did not exit" if !$exited;
    }

    print {$write_handle} encode_json({ started => scalar(@started), errors => \@errors }), "\n";
}

my @readers;
my @pids;
for my $index (1 .. $PROCESS_COUNT) {
    pipe(my $reader, my $writer) or die "pipe failed: $!\n";
    my $pid = fork() // die "fork failed: $!\n";
    if (!$pid) {
        close($reader);
        run_process($writer);
        close($writer);
        POSIX::_exit(0);
    }
    close($writer);
    push @readers, $reader;
    push @pids, $pid;
}

my $started_total = 0;
my @all_errors;
for my $index (0 .. $#pids) {
    my $reader = $readers[$index];
    my $line = <$reader>;
    waitpid($pids[$index], 0);
    die "process $index returned no result\n" if !defined($line);
    my $summary = decode_json($line);
    $started_total += $summary->{started};
    push @all_errors, @{ $summary->{errors} };
}

my $expected_total = $PROCESS_COUNT * $CALLS_PER_PROCESS;
print "started $started_total of $expected_total commands\n";
for my $error (@all_errors) {
    print "error: $error\n";
}
die "not every exec call started a command\n" if @all_errors || $started_total != $expected_total;

print "all tests passed\n";

exit(0);
