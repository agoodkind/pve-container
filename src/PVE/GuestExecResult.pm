package PVE::GuestExecResult;

use strict;
use warnings;

use Fcntl qw(O_RDONLY);
use File::Path qw(make_path remove_tree);
use JSON;
use MIME::Base64 qw(encode_base64);

use PVE::ProcFSTools;
use PVE::Tools;

my %RESULT_ROOT = (lxc => '/run/pve/lxc-exec', qemu => '/run/pve/qemu-exec');
my $RESULT_LOCK = '/run/lock/pve-guest-exec.lck';
my $RESULT_TTL = 3600;
my $ORPHAN_TTL = 7200;
my $PAYLOAD_CAPACITY = 256 * 1024 * 1024;
my $RECORD_CAPACITY = 1024;
my $OUTPUT_LIMIT = 1024 * 1024;
my $RESERVED_BYTES = 2 * $OUTPUT_LIMIT;
my $ID_BYTES = 6;
my $ID_ATTEMPTS = 10;

sub output_limit {
    return $OUTPUT_LIMIT;
}

sub with_lock {
    my ($code) = @_;

    my $result = PVE::Tools::lock_file($RESULT_LOCK, 10, $code);
    die $@ if $@;
    return $result;
}

sub result_directory {
    my ($kind, $vmid, $exec_id) = @_;

    die "unknown guest kind\n" if !exists($RESULT_ROOT{$kind});
    die "invalid guest identifier\n" if !defined($vmid) || $vmid !~ m/\A(\d+)\z/;
    my $guest_number = $1;
    die "invalid command identifier\n" if !defined($exec_id) || $exec_id !~ m/\A(\d+)\z/;
    return "$RESULT_ROOT{$kind}/$guest_number/$1";
}

sub remove_result {
    my ($directory) = @_;

    remove_tree($directory, { error => \my $errors });
    die "unable to delete the saved command result\n" if @$errors;
}

# Every operation uses the host lock while inspecting or changing result storage.
sub expire_and_measure {
    my ($record_count, $payload_bytes) = (0, 0);
    my $now = time();

    for my $root (values %RESULT_ROOT) {
        next if !-e $root;
        opendir(my $root_handle, $root) or die "unable to read command result storage: $!\n";
        for my $vmid_name (readdir($root_handle)) {
            next if $vmid_name !~ m/\A(\d+)\z/;
            my $vmid_directory = "$root/$1";
            opendir(my $vmid_handle, $vmid_directory)
                or die "unable to read guest result storage: $!\n";
            for my $id_name (readdir($vmid_handle)) {
                next if $id_name !~ m/\A(\d+)\z/;
                my $directory = "$vmid_directory/$1";
                my $reference_time = (stat("$directory/status"))[9];
                my $time_to_live = $RESULT_TTL;
                if (!defined($reference_time)) {
                    $reference_time = (stat($directory))[9];
                    $time_to_live = $ORPHAN_TTL;
                }
                die "unable to inspect command result storage: $!\n"
                    if !defined($reference_time);
                if ($now - $reference_time > $time_to_live) {
                    remove_result($directory);
                    next;
                }
                $record_count++;
                if (-e "$directory/status") {
                    for my $stream ('stdout', 'stderr') {
                        next if !-e "$directory/$stream";
                        my $size = -s "$directory/$stream";
                        die "unable to measure saved command output: $!\n" if !defined($size);
                        $payload_bytes += $size;
                    }
                } else {
                    $payload_bytes += $RESERVED_BYTES;
                }
            }
            closedir($vmid_handle);
        }
        closedir($root_handle);
    }
    return ($record_count, $payload_bytes);
}

sub reserve {
    my ($kind, $vmid) = @_;

    return with_lock(sub {
        my ($record_count, $payload_bytes) = expire_and_measure();
        die "command result storage capacity is full; acknowledge completed results before execution\n"
            if $record_count >= $RECORD_CAPACITY
            || $payload_bytes + $RESERVED_BYTES > $PAYLOAD_CAPACITY;

        my $directory = result_directory($kind, $vmid, 1);
        $directory =~ s!/1\z!!;
        make_path($directory, { mode => 0700 });
        die "unable to protect command result storage: $!\n"
            if chmod(0700, $RESULT_ROOT{$kind}, $directory) != 2;

        for (1 .. $ID_ATTEMPTS) {
            sysopen(my $random_handle, '/dev/urandom', O_RDONLY)
                or die "unable to open /dev/urandom: $!\n";
            my $read_count = sysread($random_handle, my $random_bytes, $ID_BYTES);
            close($random_handle);
            die "unable to read /dev/urandom\n"
                if !defined($read_count) || $read_count != $ID_BYTES;
            my $exec_id = unpack('Q>', "\0\0" . $random_bytes);
            die "invalid generated command identifier\n" if $exec_id !~ m/\A(\d+)\z/;
            $exec_id = $1;
            next if $exec_id < 1;
            my $result_directory = result_directory($kind, $vmid, $exec_id);
            return 0 + $exec_id if mkdir($result_directory, 0700);
            die "unable to reserve command result storage: $!\n" if !$!{EEXIST};
        }
        die "unable to allocate a command identifier\n";
    });
}

sub worker_started {
    my ($kind, $vmid, $exec_id) = @_;

    with_lock(sub {
        my $directory = result_directory($kind, $vmid, $exec_id);
        my $starttime = PVE::ProcFSTools::read_proc_starttime($$);
        die "unable to read the command worker start time\n" if !$starttime;
        PVE::Tools::file_set_contents("$directory/worker", "$$ $starttime", 0600);
    });
}

sub complete {
    my ($kind, $vmid, $exec_id, $status, $captured) = @_;

    with_lock(sub {
        my $directory = result_directory($kind, $vmid, $exec_id);
        for my $stream ('stdout', 'stderr') {
            die "command output exceeds its reserved capacity\n"
                if length($captured->{$stream}) > $OUTPUT_LIMIT;
            PVE::Tools::file_set_contents("$directory/$stream", $captured->{$stream}, 0600);
        }
        # The status file marks a complete saved result.
        PVE::Tools::file_set_contents("$directory/status", encode_json($status), 0600);
    });
}

sub read {
    my ($kind, $vmid, $exec_id) = @_;

    return with_lock(sub {
        expire_and_measure();
        my $directory = result_directory($kind, $vmid, $exec_id);
        my $guest_label = "container '$vmid'";
        $guest_label = "VM $vmid" if $kind eq 'qemu';
        die "no stored result for command $exec_id in $guest_label\n" if !-d $directory;
        if (!-e "$directory/status") {
            if (-e "$directory/worker") {
                my $worker = PVE::Tools::file_get_contents("$directory/worker");
                die "invalid command worker record\n" if $worker !~ m/\A(\d+) (\d+)\z/;
                my ($pid, $starttime) = ($1, $2);
                my $running = PVE::ProcFSTools::check_process_running($pid, $starttime);
                die "command outcome is uncertain after worker interruption; do not replay the command\n"
                    if !$running;
            }
            return { exited => 0 };
        }

        my $status = decode_json(PVE::Tools::file_get_contents("$directory/status"));
        die "execution of command $exec_id in $guest_label failed: $status->{error}\n"
            if defined($status->{error});
        die "saved command result omits its exit code\n" if !defined($status->{exitcode});
        my $result = { exited => 1, exitcode => 0 + $status->{exitcode} };
        for my $stream (['stdout', 'out-data'], ['stderr', 'err-data']) {
            my $content = PVE::Tools::file_get_contents("$directory/$stream->[0]", $OUTPUT_LIMIT);
            $result->{$stream->[1]} = encode_base64($content, '');
        }
        for my $flag ('out-truncated', 'err-truncated', 'timed-out') {
            $result->{$flag} = 1 if $status->{$flag};
        }
        return $result;
    });
}

sub acknowledge {
    my ($kind, $vmid, $exec_id) = @_;

    return with_lock(sub {
        expire_and_measure();
        my $directory = result_directory($kind, $vmid, $exec_id);
        return undef if !-d $directory;
        die "command $exec_id has not completed; acknowledgment requires a completed result\n"
            if !-e "$directory/status";
        remove_result($directory);
        return undef;
    });
}

1;
