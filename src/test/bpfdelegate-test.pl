#!/usr/bin/perl

use strict;
use warnings;

use lib qw(..);

use PVE::API2::LXC;
use PVE::API2::LXC::Config;
use PVE::LXC;
use PVE::LXC::Config;
use PVE::RPCEnvironment;

my $rpcenv = PVE::RPCEnvironment->init('cli');
$rpcenv->init_request(userconfig => 'bpfdelegate-test.cfg');

my $vmid = 100;

my $full_value = join(
    ',',
    'cmds=prog_load;map_create;btf_load',
    'maps=hash',
    'progs=sched_cls;socket_filter',
    'attachs=tcx_ingress;tcx_egress;cgroup_inet_ingress',
);

sub check_parse_ok {
    my ($value) = @_;

    my $parsed = eval { PVE::LXC::Config->parse_bpf_delegate($value) };
    die "value '$value' was rejected: $@" if $@;
    print "PARSE OK:$value\n";
    return $parsed;
}

sub check_parse_rejected {
    my ($value) = @_;

    eval { PVE::LXC::Config->parse_bpf_delegate($value) };
    die "value '$value' was accepted\n" if !$@;
    print "PARSE REJECTED:$value\n";
}

sub run_perm_check {
    my ($user, $old_value, $new_value, $unprivileged) = @_;

    my $oldconf = {};
    $oldconf->{bpfdelegate} = $old_value if defined($old_value);
    my $newconf = {};
    my $delete = [];
    if (defined($new_value)) {
        $newconf->{bpfdelegate} = $new_value;
    } else {
        $delete = ['bpfdelegate'];
    }

    eval {
        PVE::LXC::check_ct_modify_config_perm(
            $rpcenv, $user, $vmid, undef, $oldconf, $newconf, $delete, $unprivileged,
        );
    };
    return $@;
}

sub check_perm_ok {
    my ($user, $old_value, $new_value, $unprivileged) = @_;

    my $error = run_perm_check($user, $old_value, $new_value, $unprivileged);
    die "unexpected permission error for $user: $error" if $error;
    print "PERM OK:$user\n";
}

sub check_perm_denied {
    my ($user, $old_value, $new_value, $unprivileged) = @_;

    my $error = run_perm_check($user, $old_value, $new_value, $unprivileged);
    die "permission check for $user passed\n" if !$error;
    print "PERM DENIED:$user:$error";
}

my $parsed = check_parse_ok($full_value);
die "unexpected parsed cmds '$parsed->{cmds}'\n"
    if $parsed->{cmds} ne 'prog_load;map_create;btf_load';
check_parse_ok('cmds=prog_load');
check_parse_ok('attachs=cgroup_inet_ingress;tcx_egress');
check_parse_rejected('cmds=any');
check_parse_rejected('cmds=prog_load;any');
check_parse_rejected('cmds=0x4');
check_parse_rejected('cmds=4');
check_parse_rejected('cmds=unspec');
check_parse_rejected('cmds=PROG_LOAD');
check_parse_rejected('cmds=bpf_prog_load');
check_parse_rejected('cmds=prog_load;prog_load');
check_parse_rejected('cmds=prog_load:map_create');
check_parse_rejected('cmds=');
check_parse_rejected('maps=prog_load');
check_parse_rejected('unknown=hash');

my $conf = { bpfdelegate => $full_value };
my $hook_line = PVE::LXC::make_bpf_delegate_hook_config($conf, $vmid, 1);
my $expected_hook_line =
    "lxc.hook.start-host = /usr/bin/perl"
    . " -e 'use PVE::LXC; PVE::LXC::bpf_delegate_start_host(\@ARGV)'"
    . " $vmid 'cmds=prog_load:map_create:btf_load' 'maps=hash'"
    . " 'progs=sched_cls:socket_filter'"
    . " 'attachs=tcx_ingress:tcx_egress:cgroup_inet_ingress'\n";
die "unexpected hook line\nneed '$expected_hook_line'\ngot '$hook_line'\n"
    if $hook_line ne $expected_hook_line;
print "HOOK:$hook_line";

die "a container without bpfdelegate got a hook line\n"
    if PVE::LXC::make_bpf_delegate_hook_config({}, $vmid, 1) ne '';
eval { PVE::LXC::make_bpf_delegate_hook_config($conf, $vmid, 0) };
die "a privileged container got a hook line\n" if !$@;

check_perm_ok('root@pam', undef, $full_value, 1);
check_perm_ok('alice@pve', undef, $full_value, 1);
check_perm_denied('bob@pve', undef, $full_value, 1);
check_perm_denied('carol@pve', undef, $full_value, 1);
check_perm_denied('alice@pve', undef, $full_value, 0);

check_perm_ok('bob@pve', $full_value, $full_value, 1);
check_perm_ok('carol@pve', $full_value, $full_value, 1);
check_perm_ok('bob@pve', 'cmds=map_create', 'cmds=map_create;prog_load', 1);
check_perm_denied('bob@pve', 'cmds=map_create', 'cmds=map_create;prog_load;btf_load', 1);

check_perm_denied('bob@pve', 'cmds=prog_load;map_create', 'cmds=prog_load', 1);
check_perm_ok('alice@pve', $full_value, undef, 1);
check_perm_denied('bob@pve', $full_value, undef, 1);
check_perm_ok('bob@pve', 'cmds=prog_load', undef, 1);

my $method_info = PVE::API2::LXC::Config->map_method_by_name('update_vm');
my $api_privileges = $method_info->{permissions}->{check}->[2];
for my $user ('bob@pve', 'carol@pve') {
    my $allowed = $rpcenv->check_vm_perm($user, $vmid, undef, $api_privileges, 1, 1);
    die "the API level check rejected user $user\n" if !$allowed;
}
my $dave_allowed = $rpcenv->check_vm_perm('dave@pve', $vmid, undef, $api_privileges, 1, 1);
die "the API level check admitted dave\@pve\n" if $dave_allowed;
print "API level check: " . scalar(@$api_privileges) . " privileges\n";

my $guest_methods = {
    exec => 'VM.Guest.Exec',
    exec_status => 'VM.Guest.Exec',
    file_write => 'VM.Guest.FileWrite',
    file_read => 'VM.Guest.FileRead',
};

# Each token role has one guest privilege. The owning user has all three.
my $guest_tokens = {
    'erin@pve!exec' => 'VM.Guest.Exec',
    'erin@pve!read' => 'VM.Guest.FileRead',
    'erin@pve!write' => 'VM.Guest.FileWrite',
};

for my $name (sort keys %$guest_methods) {
    my $info = PVE::API2::LXC->map_method_by_name($name);
    die "method $name is not registered\n" if !$info;
    my $check = $info->{permissions}->{check};

    for my $token (sort keys %$guest_tokens) {
        my $allowed = $rpcenv->check_vm_perm($token, $vmid, undef, $check->[2], 0, 1);
        my $should_pass = $guest_tokens->{$token} eq $guest_methods->{$name};
        die "token $token was rejected for $name\n" if $should_pass && !$allowed;
        die "token $token passed for $name\n" if !$should_pass && $allowed;
        print "GUEST PERM:$name:$token:" . ($allowed ? 'allowed' : 'denied') . "\n";
    }

    for my $user ('erin@pve', 'root@pam') {
        die "user $user was rejected for $name\n"
            if !$rpcenv->check_vm_perm($user, $vmid, undef, $check->[2], 0, 1);
    }
    for my $user ('alice@pve', 'dave@pve') {
        die "user $user passed for $name\n"
            if $rpcenv->check_vm_perm($user, $vmid, undef, $check->[2], 0, 1);
    }
}

print "all tests passed\n";

exit(0);
