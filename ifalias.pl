
# Drop it in /usr/share/snmp/ifalias.pl and insert 'perl do "/usr/share/snmp/ifalias.pl"' into snmp config somewhere.

use NetSNMP::agent (':all');
use NetSNMP::ASN qw(ASN_OCTET_STR ASN_INTEGER);
use strict;

sub ifalias_handler {
	my ($handler, $registration_info, $request_info, $requests) = @_;
	my $request;

	my $i2a;
	foreach my $if (</sys/class/net/*>) {
		if (-e "$if/ifindex") {
			open R, "<$if/ifindex";
			my $i = <R>;
			chomp $i;
			close R;

			open R, "<$if/ifalias";
			$i2a->{$i} = <R>;
			close R;

			chomp($i2a->{$i});
		}
	}

	my @ifi = sort { $a <=> $b } keys %$i2a;

	for($request = $requests; $request; $request = $request->next()) {
		my $oid = $request->getOID();

		my @x = $oid->to_array;

		if ($request_info->getMode() == MODE_GET) {
			$request->setValue(ASN_OCTET_STR, $i2a->{$x[-1]}) if defined $i2a->{$x[-1]};
		} elsif ($request_info->getMode() == MODE_GETNEXT) {
			my $c = 0;

			if (scalar(@x) == 12) {
				foreach (@ifi) {
					if ($ifi[$c++] == $x[-1]) {
						last;
					}
				}
			}

			if ($c < scalar(@ifi)) {
				$request->setOID(".1.3.6.1.2.1.31.1.1.1.18.$ifi[$c]");
				$request->setValue(ASN_OCTET_STR, $i2a->{$ifi[$c]} // "");
			}
		}
	}
}

my $agent = new NetSNMP::agent();
$agent->register("ifaliases", ".1.3.6.1.2.1.31.1.1.1.18", \&ifalias_handler);
