# performancecopilot.metrics.fedora.linux_system_roles.private_metrics_subrole_pcp

Installs and configures the [Performance Co-Pilot](https://fedora.linux_system_roles.private_metrics_subrole_pcp.io/) toolkit.

## Requirements

Uses features of PCP v5 and later.

## Role Variables

### fedora.linux_system_roles.private_metrics_subrole_pcp_rest_api: true

Enable the PCP REST APIs and log discovery via the [pmproxy(1)](http://man7.org/linux/man-pages/man1/pmproxy.1.html) service.  Default: false.

### fedora.linux_system_roles.private_metrics_subrole_pcp_pmlogger_interval: 60

Default logging interval for [pmlogger(1)](http://man7.org/linux/man-pages/man1/pmlogger.1.html) archives for logging groups that do not set an explicit sampling interval.

### fedora.linux_system_roles.private_metrics_subrole_pcp_pmlogger_discard: 14

After some period, old PCP archives are discarded.  This period is 14 days by default, but may be changed using this variable.  Some special values are recognized for the period, namely '0' to keep no archives beyond the current one, and 'forever' or never to prevent any archives being discarded.  Note that the semantics of discard are that it is measured from the time of last modification of each archive, and not from the current day.

### fedora.linux_system_roles.private_metrics_subrole_pcp_archive_dir: /var/log/fedora.linux_system_roles.private_metrics_subrole_pcp/pmlogger

Default location for [pmlogger(1)](http://man7.org/linux/man-pages/man1/pmlogger.1.html) archives, per-host directories containing daily performance metric archives will be created here when pmlogger is enabled.  When [pmproxy(1)](http://man7.org/linux/man-pages/man1/pmproxy.1.html) is running with archive discovery enabled, it monitors this location.

### fedora.linux_system_roles.private_metrics_subrole_pcp_target_hosts: []

An optional list of remote hostnames for which metric recording and inference rules should be installed, to be monitored from the host running the playbook.  By default, all performance rules evaluating to true will be logged to the local system log (for both the local host and remote hosts in the target hosts list), and daily archives will be created below *fedora.linux_system_roles.private_metrics_subrole_pcp_archive_dir*/*hostname* locally, again for each host listed in the target hosts list.

### fedora.linux_system_roles.private_metrics_subrole_pcp_pmie_endpoint: ''

Send inference events to the given webhook endpoint (URL) from [pmie(1)](http://man7.org/linux/man-pages/man1/pmie.1.html) performance rules.  The default is to log these events into the local system log only.

### fedora.linux_system_roles.private_metrics_subrole_pcp_single_control: 0

Specifies whether the fedora.linux_system_roles.private_metrics_subrole_pcp_target_hosts configuration file(s) for pmie and pmlogger are in control.d form (the default) or in the single file form where /*etc*/*fedora.linux_system_roles.private_metrics_subrole_pcp*/*pmlogger*/*control* and /*etc*/*fedora.linux_system_roles.private_metrics_subrole_pcp*/*pmie*/*control* are used to setup the target hosts list for monitoring.

### fedora.linux_system_roles.private_metrics_subrole_pcp_pmcd_localonly: 0

Enable remote host connections to the [pmcd(1)](http://man7.org/linux/man-pages/man1/pmcd.1.html) service.  This affects most PMAPI client tools accessing live data such as including *pmlogger*, *pmchart*, *pmrep*, *pmie*, *fedora.linux_system_roles.private_metrics_subrole_pcp-dstat*, and so on

### fedora.linux_system_roles.private_metrics_subrole_pcp_pmproxy_localonly: 0

Enable remote host connections to the [pmproxy(1)](http://man7.org/linux/man-pages/man1/pmproxy.1.html) service.  This affects client tools using the REST API such as [grafana-fedora.linux_system_roles.private_metrics_subrole_pcp](https://grafana-fedora.linux_system_roles.private_metrics_subrole_pcp.readthedocs.io/) and PMAPI client tools using the protocol proxying features of *pmproxy*.

### fedora.linux_system_roles.private_metrics_subrole_pcp_pmlogger_localonly: 1

Enable remote host connections to the [pmlogger(1)](http://man7.org/linux/man-pages/man1/pmlogger.1.html) service.  This affects the optional [pmlc(1)](http://man7.org/linux/man-pages/man1/pmlc.1.html) utility.

### fedora.linux_system_roles.private_metrics_subrole_pcp_optional_agents: []

Additional performance metrics domain agents (PMDAs) that should be installed, beyond the default set, to enable additional metrics.  The array provided should contain shortened names for each PMDA to be enabled, such as "kvm".

### fedora.linux_system_roles.private_metrics_subrole_pcp_optional_packages: []

Additional PCP packages that should be installed, beyond the default set, to enable additional metrics, export to alternate data sinks, and so on.

```yaml
fedora.linux_system_roles.private_metrics_subrole_pcp_explicit_labels:
 environment: production

fedora.linux_system_roles.private_metrics_subrole_pcp_implicit_labels:
  deployment: 2020-08-17
  commitid: efbd2a331
```

Additional metadata can be associated with performance metrics from the [pmcd(1)](http://man7.org/linux/man-pages/man1/pmcd.1.html) service.  These are typically name=value pairs.  Explicit labels will be used in calculating time series identifiers seen by the [pmseries(1)](http://man7.org/linux/man-pages/man1/pmseries.1.html) command and [grafana-fedora.linux_system_roles.private_metrics_subrole_pcp](https://grafana-fedora.linux_system_roles.private_metrics_subrole_pcp.readthedocs.io/en/latest/index.html), and implicit labels will not.

```yaml
fedora.linux_system_roles.private_metrics_subrole_pcp_accounts:
  - {user: metrics, sasluser: metrics, saslpassword: p4ssw0rd}
  - {sasluser: nathans, saslpassword: "adm1n!"}
```

Configures access to system resources for accounts used by PCP.  The *user* setting configures a local user (system) account.  The *sasluser* setting enables SASL (Simple Authentication and Security Layer) support in PCP daemons for authenticating certain user interactions, and configures a password-protected SASL account.  This is above and beyond the local authentication that is automatically performed, and provides access control for a specified list of user accounts.  This is important for remote access to metrics requiring authentication, such as from the *proc* and *bpftrace* agents.

## Dependencies

None.

## Example Playbooks

Basic PCP setup with monitoring suited for a single host.

```yaml
- hosts: all
  roles:
    - role: performancecopilot.metrics.fedora.linux_system_roles.private_metrics_subrole_pcp
      vars:
        fedora.linux_system_roles.private_metrics_subrole_pcp_pmlogger_interval: 10
        fedora.linux_system_roles.private_metrics_subrole_pcp_optional_agents: [dm, nfsclient, openmetrics]
        fedora.linux_system_roles.private_metrics_subrole_pcp_explicit_labels:
          environment: production
```

Central PCP setup for monitoring of several remote hosts.

```yaml
- hosts: monitoring
  roles:
    - role: performancecopilot.metrics.fedora.linux_system_roles.private_metrics_subrole_pcp
      vars:
        fedora.linux_system_roles.private_metrics_subrole_pcp_pmlogger_interval: 10
        fedora.linux_system_roles.private_metrics_subrole_pcp_pmlogger_discard: 5
        fedora.linux_system_roles.private_metrics_subrole_pcp_target_hosts: [slip, slop, slap]
        fedora.linux_system_roles.private_metrics_subrole_pcp_rest_api: true
```

## License

MIT

## Author Information

Official role for PCP, maintained by the PCP developers <fedora.linux_system_roles.private_metrics_subrole_pcp@groups.io>
