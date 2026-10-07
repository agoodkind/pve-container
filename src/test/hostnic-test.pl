#!/usr/bin/perl

use strict;
use warnings;

use lib qw(..);

use File::Temp qw(tempdir);

use PVE::API2::LXC::Config;
use PVE::LXC;
use PVE::LXC::Config;
use PVE::LXC::Create;
use PVE::RPCEnvironment;

my $rpcenv = PVE::RPCEnvironment->init('cli');
$rpcenv->init_request(userconfig => 'hostnic-test.cfg');

my $vmid = 100;

sub check_equal {
    my ($label, $got, $expected) = @_;

    die "unexpected result for $label\nneed '$expected'\ngot '$got'\n" if $got ne $expected;
    print "OK:$label\n";
}

sub check_parse_ok {
    my ($value) = @_;

    my $parsed = eval { PVE::LXC::Config->parse_hostnic($value) };
    die "value '$value' was rejected: $@" if $@;
    print "PARSE OK:$value\n";
    return $parsed;
}

sub check_parse_rejected {
    my ($value) = @_;

    eval { PVE::LXC::Config->parse_hostnic($value) };
    die "value '$value' was accepted\n" if !$@;
    print "PARSE REJECTED:$value\n";
}

sub check_conflict_rejected {
    my ($label, $conf, $expected_pattern) = @_;

    eval { PVE::LXC::Config->check_hostnic_conflicts($conf) };
    die "conflict '$label' was accepted\n" if !$@;
    die "conflict '$label' failed with an unexpected error: $@" if $@ !~ $expected_pattern;
    print "CONFLICT REJECTED:$label:$@";
}

my $minimal = check_parse_ok('link=nic1v1');
check_equal('minimal link', $minimal->{link}, 'nic1v1');
check_equal('default name', $minimal->{name}, 'nic1v1');
check_equal('default up', $minimal->{up}, 0);
die "minimal value has an hwaddr\n" if defined($minimal->{hwaddr});
die "minimal value has an mtu\n" if defined($minimal->{mtu});

my $full = check_parse_ok('link=nic1v1,name=mwanbr,hwaddr=AA:BB:CC:DD:EE:01,mtu=1500,up=1');
check_equal('full name', $full->{name}, 'mwanbr');
check_equal('full hwaddr', $full->{hwaddr}, 'AA:BB:CC:DD:EE:01');
check_equal('full mtu', $full->{mtu}, 1500);
check_equal('full up', $full->{up}, 1);

check_parse_ok('link=a.b-c_d');
check_parse_ok('link=123456789012345');
check_parse_rejected('name=mwanbr');
check_parse_rejected('link=1234567890123456');
check_parse_rejected('link=nic/1');
check_parse_rejected('link=nic 1');
check_parse_rejected('link=');
check_parse_rejected('link=nic1v1,name=1234567890123456');
check_parse_rejected('link=nic1v1,name=a/b');
check_parse_rejected('link=nic1v1,hwaddr=zz');
check_parse_rejected('link=nic1v1,mtu=63');
check_parse_rejected('link=nic1v1,mtu=65536');
check_parse_rejected('link=nic1v1,up=maybe');
check_parse_rejected('link=nic1v1,unknown=1');

my $generated_conf = {
    net0 => 'name=eth0,bridge=vmbr0,type=veth',
    hostnic0 => 'link=nic1v1,name=mwanbr,up=1',
    hostnic1 => 'link=nic2v1,hwaddr=AA:BB:CC:DD:EE:02,mtu=1400',
    hostnic9 => 'link=nic3v1',
};
my $expected_lines = join(
    '',
    "lxc.net.32.type = phys\n",
    "lxc.net.32.link = nic1v1\n",
    "lxc.net.32.name = mwanbr\n",
    "lxc.net.32.flags = up\n",
    "lxc.net.33.type = phys\n",
    "lxc.net.33.link = nic2v1\n",
    "lxc.net.33.name = nic2v1\n",
    "lxc.net.33.hwaddr = AA:BB:CC:DD:EE:02\n",
    "lxc.net.33.mtu = 1400\n",
    "lxc.net.41.type = phys\n",
    "lxc.net.41.link = nic3v1\n",
    "lxc.net.41.name = nic3v1\n",
);
check_equal('generated lines', PVE::LXC::make_hostnic_config($generated_conf), $expected_lines);
check_equal('no hostnic lines', PVE::LXC::make_hostnic_config({ net0 => 'name=eth0' }), '');

my $max_net_index = 31;
for my $index (0 .. 9) {
    my $lxc_index = PVE::LXC::Config->hostnic_lxc_net_index("hostnic$index");
    die "hostnic$index collides with a netN index\n" if $lxc_index <= $max_net_index;
}
print "OK:index range\n";

eval { PVE::LXC::Config->hostnic_lxc_net_index('hostnic10') };
check_equal('index limit', $@, "'hostnic10' is not a valid hostnic key.\n");

check_conflict_rejected(
    'same link',
    { hostnic0 => 'link=nic1v1,name=a', hostnic1 => 'link=nic1v1,name=b' },
    qr/hostnic1: hostnic0 already uses host interface 'nic1v1'\./,
);
check_conflict_rejected(
    'same name',
    { hostnic0 => 'link=nic1v1,name=mwanbr', hostnic1 => 'link=nic2v1,name=mwanbr' },
    qr/hostnic1: hostnic0 already uses container interface name 'mwanbr'\./,
);
check_conflict_rejected(
    'default name equals an explicit name',
    { hostnic0 => 'link=nic1v1', hostnic1 => 'link=nic2v1,name=nic1v1' },
    qr/hostnic1: hostnic0 already uses container interface name 'nic1v1'\./,
);
check_conflict_rejected(
    'name equals a netN name',
    { net1 => 'name=eth1,bridge=vmbr0', hostnic0 => 'link=nic1v1,name=eth1' },
    qr/hostnic0: net1 already uses container interface name 'eth1'\./,
);
check_conflict_rejected(
    'default name equals a netN name',
    { net0 => 'name=nic1v1,bridge=vmbr0', hostnic0 => 'link=nic1v1' },
    qr/hostnic0: net0 already uses container interface name 'nic1v1'\./,
);

PVE::LXC::Config->check_hostnic_conflicts($generated_conf);
PVE::LXC::Config->check_hostnic_conflicts({
    hostnic0 => 'link=nic1v1,name=a',
    hostnic1 => 'link=nic1v2,name=nic1v1',
});
print "OK:distinct links and names\n";

my $pending_conf = {
    net0 => 'name=eth0,bridge=vmbr0',
    hostnic0 => 'link=nic1v1,name=mwanbr',
    pending => {
        hostnic1 => 'link=nic1v1,name=other',
    },
};
eval { PVE::LXC::Config->check_pending_hostnic_conflicts($pending_conf) };
die "a pending duplicate link was accepted\n" if !$@;
print "PENDING REJECTED:$@";

$pending_conf->{pending}->{delete} = 'hostnic0';
PVE::LXC::Config->check_pending_hostnic_conflicts($pending_conf);
print "OK:pending delete resolves the conflict\n";

my $net_dir = tempdir(CLEANUP => 1);
mkdir "$net_dir/plain0" or die "mkdir plain0: $!\n";
mkdir "$net_dir/br0" or die "mkdir br0: $!\n";
mkdir "$net_dir/br0/bridge" or die "mkdir br0/bridge: $!\n";

PVE::LXC::check_hostnic_links({ hostnic0 => 'link=plain0' }, $net_dir);
PVE::LXC::check_hostnic_links({ net0 => 'name=eth0' }, $net_dir);
PVE::LXC::check_hostnic_links({ hostnic0 => 'link=lo' });
print "OK:existing links\n";

eval { PVE::LXC::check_hostnic_links({ hostnic0 => 'link=missing0' }, $net_dir) };
die "a missing host interface was accepted\n"
    if $@ !~ /hostnic0: Host interface 'missing0' does not exist\./;
print "START REJECTED:$@";

eval { PVE::LXC::check_hostnic_links({ hostnic2 => 'link=br0' }, $net_dir) };
die "a bridge was accepted\n" if $@ !~ /hostnic2: Host interface 'br0' is a Linux bridge\./;
print "START REJECTED:$@";

sub run_perm_check {
    my ($user, $old_value, $new_value) = @_;

    my $oldconf = {};
    $oldconf->{hostnic0} = $old_value if defined($old_value);
    my $newconf = {};
    my $delete = [];
    if (defined($new_value)) {
        $newconf->{hostnic0} = $new_value;
    } else {
        $delete = ['hostnic0'];
    }

    eval {
        PVE::LXC::check_ct_modify_config_perm(
            $rpcenv, $user, $vmid, undef, $oldconf, $newconf, $delete, 1,
        );
    };
    return $@;
}

sub check_perm_ok {
    my ($label, $user, $old_value, $new_value) = @_;

    my $error = run_perm_check($user, $old_value, $new_value);
    die "unexpected permission error for $label: $error" if $error;
    print "PERM OK:$label\n";
}

sub check_perm_denied {
    my ($label, $user, $old_value, $new_value) = @_;

    my $error = run_perm_check($user, $old_value, $new_value);
    die "permission check for $label passed\n" if !$error;
    print "PERM DENIED:$label:$error";
}

my $link_one = 'link=nic1v1';
my $link_two = 'link=nic2v1';

check_perm_ok('root set', 'root@pam', undef, $link_two);
check_perm_ok('alice set permitted link', 'alice@pve', undef, $link_one);
check_perm_denied('alice set other link', 'alice@pve', undef, $link_two);
check_perm_denied('alice change to other link', 'alice@pve', $link_one, $link_two);
check_perm_denied('alice change from other link', 'alice@pve', $link_two, $link_one);
check_perm_ok('alice delete permitted link', 'alice@pve', $link_one, undef);
check_perm_denied('alice delete other link', 'alice@pve', $link_two, undef);
check_perm_denied('bob set without link privilege', 'bob@pve', undef, $link_one);
check_perm_denied('bob delete without link privilege', 'bob@pve', $link_one, undef);
check_perm_denied('carol set without vm privilege', 'carol@pve', undef, $link_one);
check_perm_denied('carol delete without vm privilege', 'carol@pve', $link_one, undef);
check_perm_denied('dave set', 'dave@pve', undef, $link_one);

my $method_info = PVE::API2::LXC::Config->map_method_by_name('update_vm');
my $api_privileges = $method_info->{permissions}->{check}->[2];
for my $user ('alice@pve', 'bob@pve') {
    my $allowed = $rpcenv->check_vm_perm($user, $vmid, undef, $api_privileges, 1, 1);
    die "the API level check rejected user $user\n" if !$allowed;
}
for my $user ('carol@pve', 'dave@pve') {
    my $allowed = $rpcenv->check_vm_perm($user, $vmid, undef, $api_privileges, 1, 1);
    die "the API level check admitted user $user\n" if $allowed;
}
print "API level check: " . scalar(@$api_privileges) . " privileges\n";

$rpcenv->set_user('alice@pve');
my $restored_conf = {};
PVE::LXC::Create::sanitize_and_merge_config(
    $restored_conf,
    { hostnic0 => 'link=nic1v1', memory => 256 },
    1,
    0,
);
die "a restricted restore copied hostnic0\n" if defined($restored_conf->{hostnic0});
die "a restricted restore dropped memory\n" if !defined($restored_conf->{memory});
my $root_restored_conf = {};
PVE::LXC::Create::sanitize_and_merge_config(
    $root_restored_conf, { hostnic0 => 'link=nic1v1' }, 0, 0,
);
die "an unrestricted restore dropped hostnic0\n" if !defined($root_restored_conf->{hostnic0});
print "OK:restore\n";

print "all tests passed\n";

exit(0);
