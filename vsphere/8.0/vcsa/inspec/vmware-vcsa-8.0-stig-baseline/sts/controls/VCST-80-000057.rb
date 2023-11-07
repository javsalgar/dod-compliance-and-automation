control 'VCST-80-000057' do
  title 'The vCenter STS service must be configured to limit data exposure between applications.'
  desc 'If RECYCLE_FACADES is true or if a security manager is in use, a new facade object will be created for each request. This reduces the chances that a bug in an application might expose data from one request to another.'
  desc 'check', 'At the command line, run the following command:

# grep RECYCLE_FACADES /usr/lib/vmware-sso/vmware-sts/conf/catalina.properties

Example result:

org.apache.catalina.connector.RECYCLE_FACADES=true

If "org.apache.catalina.connector.RECYCLE_FACADES" is not set to "true", this is a finding.

If the "org.apache.catalina.connector.RECYCLE_FACADES" setting does not exist, this is not a finding.'
  desc 'fix', 'Navigate to and open:

/usr/lib/vmware-sso/vmware-sts/conf/catalina.properties

Update or remove the following line:

org.apache.catalina.connector.RECYCLE_FACADES=true

Restart the service with the following command:

# vmon-cli --restart sts'
  impact 0.5
  tag check_id: 'C-62719r934593_chk'
  tag severity: 'medium'
  tag gid: 'V-258979'
  tag rid: 'SV-258979r934595_rule'
  tag stig_id: 'VCST-80-000057'
  tag gtitle: 'SRG-APP-000223-AS-000150'
  tag fix_id: 'F-62628r934594_fix'
  tag cci: ['CCI-001664']
  tag nist: ['SC-23 (3)']

  describe parse_config_file("#{input('catalinaPropertiesPath')}").params['org.apache.catalina.connector.RECYCLE_FACADES'] do
    it { should be_in [nil, 'true'] }
  end
end
