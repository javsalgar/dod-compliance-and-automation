control 'PHTN-40-000182' do
  title 'The Photon operating system must implement NIST FIPS-validated cryptography for the following: to provision digital signatures, to generate cryptographic hashes, and to protect unclassified information requiring confidentiality and cryptographic protection in accordance with applicable federal laws, Executive Orders, directives, policies, regulations, and standards.'
  desc 'Use of weak or untested encryption algorithms undermines the purposes of utilizing encryption to protect data. The operating system must implement cryptographic modules adhering to the higher standards approved by the federal government since this provides assurance they have been tested and validated.'
  desc 'check', 'At the command line, run the following command to verify FIPS is enabled for the OS:

# cat /proc/sys/crypto/fips_enabled

Example result:

1

If "fips_enabled" is not set to "1", this is a finding.'
  desc 'fix', 'Navigate to and open:

/boot/grub2/grub.cfg

Locate the boot command line arguments. An example follows:

linux /boot/$photon_linux root=$rootpartition $photon_cmdline $systemd_cmdline

Add "fips=1" to the end of the line so it reads as follows:

linux /boot/$photon_linux root=$rootpartition $photon_cmdline $systemd_cmdline fips=1

Note: Do not copy/paste in this example argument line. This may change in future releases. Find the similar line and append "fips=1" to it.

Reboot the system for the change to take effect.'
  impact 0.7
  tag check_id: 'C-62592r933615_chk'
  tag severity: 'high'
  tag gid: 'V-258852'
  tag rid: 'SV-258852r933617_rule'
  tag stig_id: 'PHTN-40-000182'
  tag gtitle: 'SRG-OS-000478-GPOS-00223'
  tag fix_id: 'F-62501r933616_fix'
  tag satisfies: ['SRG-OS-000478-GPOS-00223', 'SRG-OS-000396-GPOS-00176']
  tag cci: ['CCI-002450']
  tag nist: ['SC-13 b']

  describe file('/proc/sys/crypto/fips_enabled') do
    its('content') { should cmp 1 }
  end
end
