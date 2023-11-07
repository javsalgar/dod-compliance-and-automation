control 'VCRP-80-000097' do
  title 'The vCenter Envoy service log files must be sent to a central log server.'
  desc 'Writing events to a centralized management audit system offers many benefits to the enterprise over having dispersed logs. Centralized management of audit records and logs provides for efficiency in maintenance and management of records, enterprise analysis of events, and backup and archiving of event records enterprise-wide. The web server and related components are required to be capable of writing logs to centralized audit log servers.'
  desc 'check', 'By default, there is a vmware-services-envoy.conf rsyslog configuration file that includes the service logs when syslog is configured on vCenter, but it must be verified.

At the command prompt, run the following command:

# cat /etc/vmware-syslog/vmware-services-envoy.conf

Expected result:

#envoy service log
input(type="imfile"
      File="/var/log/vmware/envoy/envoy.log"
      Tag="envoy-main"
      Severity="info"
      Facility="local0")
#envoy access log
input(type="imfile"
      File="/var/log/vmware/envoy/envoy-access.log"
      Tag="envoy-access"
      Severity="info"
      Facility="local0")
#envoy init stdout
input(type="imfile"
      File="/var/log/vmware/envoy/envoy_init.log.stdout"
      Tag="envoy-stdout"
      Severity="info"
      Facility="local0")
#envoy init stderr
input(type="imfile"
      File="/var/log/vmware/envoy/envoy_init.log.stderr"
      Tag="envoy-stderr"
      Severity="info"
      Facility="local0")

If the output does not match the expected result, this is a finding.'
  desc 'fix', 'Navigate to and open:

/etc/vmware-syslog/vmware-services-envoy.conf

Create the file if it does not exist.

Set the contents of the file as follows:

#envoy service log
input(type="imfile"
      File="/var/log/vmware/envoy/envoy.log"
      Tag="envoy-main"
      Severity="info"
      Facility="local0")
#envoy access log
input(type="imfile"
      File="/var/log/vmware/envoy/envoy-access.log"
      Tag="envoy-access"
      Severity="info"
      Facility="local0")
#envoy init stdout
input(type="imfile"
      File="/var/log/vmware/envoy/envoy_init.log.stdout"
      Tag="envoy-stdout"
      Severity="info"
      Facility="local0")
#envoy init stderr
input(type="imfile"
      File="/var/log/vmware/envoy/envoy_init.log.stderr"
      Tag="envoy-stderr"
      Severity="info"
      Facility="local0")'
  impact 0.5
  tag check_id: 'C-62904r935394_chk'
  tag severity: 'medium'
  tag gid: 'V-259164'
  tag rid: 'SV-259164r935396_rule'
  tag stig_id: 'VCRP-80-000097'
  tag gtitle: 'SRG-APP-000358-WSR-000063'
  tag fix_id: 'F-62813r935395_fix'
  tag cci: ['CCI-001851']
  tag nist: ['AU-4 (1)']

  goodcontent = inspec.profile.file('vmware-services-envoy.conf')
  describe file('/etc/vmware-syslog/vmware-services-envoy.conf') do
    its('content') { should eq goodcontent }
  end
end
