#! /usr/bin/perl -w

while (<>) {
    s/#.*$//;
    next if (/^\w*$/);

    ($cipher, $key, $pt, $ct) = split ' ', $_;
    $pt =~ tr/A-Z/a-z/;
    $ct =~ tr/A-Z/a-z/;

    $tct = `./testcipher v $cipher e $key $pt`;
    chomp $tct;
    $tct =~ tr/A-Z/a-z/;
    if ($ct ne $tct) {
	print "bad: encrypt cipher=$cipher key=$key pt=$pt gave ct=$tct, should be ct=$ct\n";
    }

    $tpt = `./testcipher v $cipher d $key $ct`;
    chomp $tpt;
    $tpt =~ tr/A-Z/a-z/;
    if ($pt ne $tpt) {
	print "bad: decrypt cipher=$cipher key=$key ct=$ct gave pt=$tpt, should be pt=$pt\n";
    }
}
