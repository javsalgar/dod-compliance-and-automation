control 'PHTN-50-000217' do
  title 'The Photon operating system must configure Secure Shell (SSH) to ignore user-specific trusted hosts lists.'
  desc  'SSH trust relationships enable trivial lateral spread after a host compromise and therefore must be explicitly disabled. Individual users can have a local list of trusted remote machines, which must also be ignored while disabling host-based authentication generally.'
  desc  'rationale', ''
  desc  'check', "
    At the command line, run the following command to verify the running configuration of sshd:

    # sshd -T|&grep -i IgnoreRhosts

    Example result:

    ignorerhosts yes

    If \"IgnoreRhosts\" is not set to \"yes\", this is a finding.
  "
  desc 'fix', "
    Navigate to and open:

    /etc/ssh/sshd_config

    Ensure the \"IgnoreRhosts\" line is uncommented and set to the following:

    IgnoreRhosts yes

    At the command line, run the following command:

    # systemctl restart sshd.service
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag gid: 'V-PHTN-50-000217'
  tag rid: 'SV-PHTN-50-000217'
  tag stig_id: 'PHTN-50-000217'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  only_if('Target is a container. This control is not applicable', impact: 0.0) {
    !input('isContainer')
  }

  sshdcommand = input('sshdcommand')
  describe command("#{sshdcommand}|&grep -i IgnoreRhosts") do
    its('stdout.strip') { should cmp 'IgnoreRhosts yes' }
  end
end
