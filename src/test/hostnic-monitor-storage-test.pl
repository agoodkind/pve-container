#!/usr/bin/perl

use strict;
use warnings;

use Test::More;
use PVE::LXC;
use PVE::LXC::Config;
use PVE::LXC::Monitor;
use PVE::Storage;

# Run on a disposable node with lxc-monitord stopped. The guest must have a
# hostnic and a missing rootfs file on an existing directory storage.
my $vmid = shift // die "Specify a disposable container VMID.\n";
die "Specify a numeric VMID.\n" if $vmid !~ /\A\d+\z/;
die "The LXC monitor is running.\n" if eval { PVE::LXC::Monitor::get_monitor_socket() };

PVE::LXC::Config->lock_config($vmid, sub {
    my $conf = PVE::LXC::Config->load_config($vmid);
    die "The test container is running.\n" if PVE::LXC::check_running($vmid);
    my $hostnics = PVE::LXC::Config->get_hostnics($conf);
    die "The test requires a hostnic device.\n" if !keys %$hostnics;
    my $mount = PVE::LXC::Config->parse_volume('rootfs', $conf->{rootfs});
    my $volume = $mount->{volume};
    my ($storeid) = PVE::Storage::parse_volume_id($volume);
    my $storecfg = PVE::Storage::config();
    my $storage = PVE::Storage::storage_config($storecfg, $storeid);
    die "The test requires an existing directory storage.\n"
        if $storage->{type} ne 'dir' || !-d $storage->{path};
    die "The test rootfs file must be missing.\n" if -e PVE::Storage::path($storecfg, $volume);
    die "The skiplock flag already exists.\n" if -e "/run/lxc/skiplock-$vmid";

    my %ordinary = %$conf;
    delete @ordinary{keys %$hostnics};
    eval { PVE::LXC::vm_start($vmid, \%ordinary) };
    like($@, qr/volume '\Q$volume\E' does not exist/,
        'Without hostnic, startup continues to the real storage activation error');

    eval { PVE::LXC::vm_start($vmid, $conf, 1) };
    like($@, qr/Cannot monitor startup for container $vmid: failed to connect/,
        'With hostnic, startup rejects the missing monitor before storage activation');
    ok(!-e "/run/lxc/skiplock-$vmid", 'The rejected start does not leave a skiplock flag');
});
done_testing();
