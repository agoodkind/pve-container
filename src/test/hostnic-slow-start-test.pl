#!/usr/bin/perl

use strict;
use warnings;

use Errno qw(EWOULDBLOCK);
use Fcntl qw(:flock);
use POSIX qw(_exit);
use Test::More;
use PVE::LXC;
use PVE::LXC::Config;
use PVE::LXC::Monitor;
use PVE::RPCEnvironment;
use PVE::SRIOVLock;
use PVE::Tools qw(run_command);

# Run on a disposable node with a stopped hostnic guest. Its liblxc pre-start
# hook must take at least 70 seconds and then either succeed or reject startup.
my ($vmid, $expected) = @ARGV;
die "Specify a disposable container VMID and either running or aborted.\n"
    if !defined($vmid) || $vmid !~ /^\d+$/ || ($expected // '') !~ /\A(?:running|aborted)\z/;

my $rpcenv = PVE::RPCEnvironment->init('cli');
$rpcenv->set_user('root@pam');
my $config = PVE::LXC::Config->load_config($vmid);
die "The test requires a hostnic device.\n" if !keys(PVE::LXC::Config->get_hostnics($config)->%*);
die "Container $vmid is already running.\n" if PVE::LXC::check_running($vmid);
my $monitor = PVE::LXC::Monitor::get_monitor_socket();
pipe(my $reader, my $writer) or die "Cannot create the startup result pipe: $!\n";
my $child = fork() // die "Cannot start the test worker: $!\n";
if (!$child) {
    close($reader);
    close($monitor);
    eval {
        PVE::LXC::Config->lock_config($vmid, sub {
            my $conf = PVE::LXC::Config->load_config($vmid);
            PVE::LXC::vm_start($vmid, $conf, undef, 0);
        });
    };
    my $err = $@;
    print {$writer} $err;
    close($writer) or _exit(2);
    _exit($err ? 1 : 0);
}
close($writer);

eval {
    PVE::Tools::run_with_timeout(30, sub {
        while (1) {
            my ($type, $name, $state) = PVE::LXC::Monitor::read_lxc_message($monitor);
            die "The LXC monitor closed before STARTING.\n" if !defined($type);
            last if $type eq 'STATE' && $name eq "$vmid"
                && $state == PVE::LXC::Monitor::STATE_STARTING;
        }
    });
    sleep(63);
    open(my $lock, '>>', PVE::SRIOVLock::PATH) or die "Cannot open the attachment lock: $!\n";
    my $available = flock($lock, LOCK_EX | LOCK_NB);
    my $busy = !$available && $! == EWOULDBLOCK;
    close($lock);
    ok($busy, 'The physical attachment still excludes mutation 63 seconds after STARTING');
};
my $monitor_error = $@;
my $error = do { local $/; <$reader> };
waitpid($child, 0) == $child or die "Cannot wait for the test worker: $!\n";
my $status = $?;
open(my $lock, '>>', PVE::SRIOVLock::PATH) or die "Cannot reopen the attachment lock: $!\n";
ok(flock($lock, LOCK_EX | LOCK_NB), 'Mutation can acquire the lock after startup finishes');
close($lock);
if ($expected eq 'running') {
    is($status, 0, 'The slow startup succeeds') or diag($error);
    ok(eval { PVE::LXC::find_lxc_pid($vmid) }, 'The running container has an init PID');
    run_command(['systemctl', 'stop', "pve-container\@$vmid.service"]);
} else {
    is($status, 256, 'The rejected startup fails');
    like($error, qr/startup for container '\Q$vmid\E' failed/, 'The monitor reports the terminal state');
    my $state;
    run_command(['systemctl', 'show', "pve-container\@$vmid.service", '-p', 'ActiveState', '--value'],
        outfunc => sub { $state = shift });
    like($state, qr/\A(?:failed|inactive)\z/, 'The systemd unit has stopped');
    ok(!PVE::LXC::check_running($vmid), 'Teardown finishes before vm_start returns');
}
die $monitor_error if $monitor_error;
done_testing();
