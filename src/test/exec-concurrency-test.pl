#!/usr/bin/perl -T

# Starts commands through the exec method of PVE::API2::LXC from several processes at the same
# time, as the workers of pvedaemon do, and requires every start to return a pid.
# Each process runs the production code of exec and PVE::RESTEnvironment::fork_worker. The test
# replaces the container lookup and lxc-attach, which need a node, and the process start time
# check, which fails under the emulation of the amd64 test image.

use strict;
use warnings;

use Cwd qw(abs_path);
use File::Basename qw(basename);
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
use PVE::UPID;

my $PROCESS_COUNT = 4;
my $CALLS_PER_PROCESS = 15;
my $VMID = 9004;
my $OTHER_USER = 'other@pve!t1';
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

sub process_user {
    my ($index) = @_;

    return "svc${index}\@pve!deploy";
}

# One process: calls exec repeatedly, then polls every started command until it exits.
# rest_handler stores the user of the request in the credentials before it calls the method.
# The user of the environment is empty on every second call and belongs to another request on
# the other calls, the states that concurrent requests leave in a pvedaemon process.
sub run_process {
    my ($write_handle, $index) = @_;

    my $rpcenv = PVE::RPCEnvironment->init('priv');
    my @started;
    my @errors;
    for my $call (1 .. $CALLS_PER_PROCESS) {
        if ($call % 2) {
            $rpcenv->set_user($OTHER_USER);
        } else {
            $rpcenv->set_user(undef);
        }
        $rpcenv->set_credentials({ userid => process_user($index) });
        my $result = eval {
            $exec_info->{code}->({ vmid => $VMID, command => ['true'], timeout => 30 });
        };
        $rpcenv->set_user(undef);
        $rpcenv->set_credentials(undef);
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

    # A request without credentials gets an error and no task under another user.
    $rpcenv->set_user($OTHER_USER);
    my $without_credentials = eval {
        $exec_info->{code}->({ vmid => $VMID, command => ['true'], timeout => 30 });
    };
    $rpcenv->set_user(undef);
    if ($without_credentials || $@ !~ m/authenticated user of the request is not available/) {
        push @errors, 'exec without credentials did not fail with the user error';
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
        run_process($writer, $index);
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

# The UPID of every task records the user of the request that started it.
my %tasks_per_user;
for my $log (glob('/var/log/pve/tasks/*/UPID*')) {
    my $upid = PVE::UPID::decode(basename($log));
    next if !$upid || $upid->{type} ne 'lxcexec';
    $tasks_per_user{ $upid->{user} }++;
}
for my $index (1 .. $PROCESS_COUNT) {
    my $user = process_user($index);
    my $count = $tasks_per_user{$user} // 0;
    print "tasks of $user: $count\n";
    push @all_errors, "$user has $count tasks, expected $CALLS_PER_PROCESS"
        if $count != $CALLS_PER_PROCESS;
}
for my $user (sort keys %tasks_per_user) {
    next if $user =~ m/\Asvc\d+\@pve!deploy\z/;
    push @all_errors, "unexpected task user $user";
}

my $expected_total = $PROCESS_COUNT * $CALLS_PER_PROCESS;
print "started $started_total of $expected_total commands\n";
for my $error (@all_errors) {
    print "error: $error\n";
}
die "not every exec call started a command\n" if @all_errors || $started_total != $expected_total;

print "all tests passed\n";

exit(0);
