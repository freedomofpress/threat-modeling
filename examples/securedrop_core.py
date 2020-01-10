from threat_modeling.data_flow import Boundary, Dataflow, Datastore, Element, ExternalEntity, Process
from threat_modeling.project import ThreatModel

"""
TODO:
* Make this less verbose, either by loading from YAML or keeping some reference to the threat model in the element
definition so we don't need to explictly add them later?
"""

tm = ThreatModel("SecureDrop")
tm.description = "SecureDrop core threat model"
elements = set()
flows = set()
boundaries = []

# Users
source = ExternalEntity("source")
elements.add(source)
journalist = ExternalEntity("journalist")
elements.add(journalist)
admin = ExternalEntity("administrator")
elements.add(admin)

# Source Area
tor_browser_source = Process("Tor Browser to Source Interface")
elements.add(tor_browser_source)

# Journalist Workstation (Tails)
tor_browser_journalist = Process("Tor Browser to Journalist Interface")
elements.add(tor_browser_journalist)
encrypted_submission_in_journo = Element("Encrypted submission")
elements.add(encrypted_submission_in_journo)

# Admin Workstation (Tails)
ssh_admin = Process("SSH Access to Servers")
elements.add(ssh_admin)
tor_admin = Process("tor process")
elements.add(tor_admin)

# SecureDrop Area
hardware_firewall = Element("Dedicated pfSense hardware firewall")
elements.add(hardware_firewall)
journalist_interface = Process("Journalist Interface (ATHS)")
elements.add(journalist_interface)
source_interface = Process("Source Interface (THS)")
elements.add(source_interface)
ssh_app_interface = Process("SSH (ATHS)")
elements.add(ssh_app_interface)
ssh_app_daemon = Process ("sshd")
elements.add(ssh_app_daemon)
securedrop_app = Process("securedrop-app-code")
elements.add(securedrop_app)
in_mem_submission = Element("Submission")
elements.add(in_mem_submission)
asymmetric_encryption = Process("Encrypt with submission pubkey")
elements.add(asymmetric_encryption)
encrypted_submission = Element("Encrypted Submission")
elements.add(encrypted_submission)
app_database = Datastore("sqlite DB")
elements.add(app_database)
ossec_agent = Process("OSSEC Client")
elements.add(ossec_agent)
apt_client_app = Process("APT")
elements.add(apt_client_app)
ntp_client_app = Process("NTP")
elements.add(ntp_client_app)
dns_client_app = Process("DNS")
elements.add(dns_client_app)
securedrop_app_config = Datastore("Application config")
elements.add(securedrop_app_config)
apache_web_server = Process ("Apache")
elements.add(apache_web_server)

apt_client_mon = Process("APT")
elements.add(apt_client_mon)
ntp_client_mon = Process("NTP")
elements.add(ntp_client_mon)
dns_client_mon = Process("DNS")
elements.add(dns_client_mon)
postfix = Process("Postfix")
elements.add(postfix)
ossec_server = Process("OSSEC Server")
elements.add(ossec_server)
ssh_mon_interface = Process("SSH (ATHS)")
elements.add(ssh_mon_interface)
ssh_mon_daemon = Process ("sshd")
elements.add(ssh_mon_daemon)

# Airgap
encrypted_document = Element("encrypted submission")
elements.add(encrypted_document)
decryption = Process("Decrypt with privkey")
elements.add(decryption)
decrypted_submission = Element("decrypted submission")
elements.add(decrypted_submission)
sanitization = Process("Sanitize submission data (MAT)")
elements.add(sanitization)
sanitized_document = Element("Sanitized submission")
elements.add(sanitized_document)
printer = Element("Printer")
elements.add(printer)

# Elements not in any boundary
transfer_device = Datastore("Data Transfer Device")
elements.add(transfer_device)
export_device = Datastore("Export Device")
elements.add(export_device)
printed_documents = Element("Printed documents")
elements.add(printed_documents)

# Journalist corporate area
corp_workstation = Element("Journalist Corporate Workstation")
elements.add(corp_workstation)
corp_cms = Element("Journalist publishing system")
elements.add(corp_cms)

# External services area
fpf_apt_repository = ExternalEntity("FPF apt server")
elements.add(fpf_apt_repository)
ubuntu_apt_repository = ExternalEntity("Ubuntu apt server")
elements.add(ubuntu_apt_repository)
ntp_server = ExternalEntity("NTP server")
elements.add(ntp_server)
dns_server = ExternalEntity("DNS server")
elements.add(dns_server)
smtp_relay = ExternalEntity("SMTP relay")
elements.add(smtp_relay)

# Add all these elements now
for element in elements:
    tm.add_element(element)

# Data flows: in/to/from source area

user_interface_source = Dataflow.from_elements(source, tor_browser_source,
                                 "uses Tor browser")
flows.add(user_interface_source)
source_to_securedrop = Dataflow.from_elements(tor_browser_source, hardware_firewall,
                                "tor")
flows.add(source_to_securedrop)

# Data flows: in/to/from admin area

ssh_traffic_routed_through_tor = Dataflow.from_elements(ssh_admin, tor_admin, "ssh over LAN or tor")
flows.add(ssh_traffic_routed_through_tor)
admin_to_securedrop_app = Dataflow.from_elements(tor_admin, hardware_firewall, "tor")
flows.add(admin_to_securedrop_app)

# Data flows: in/to/from journalist area

user_interface_journalist = Dataflow.from_elements(journalist, tor_browser_journalist,
                                     "uses Tor browser (on Tails)")
flows.add(user_interface_journalist)
journalist_to_securedrop = Dataflow.from_elements(hardware_firewall, tor_browser_journalist,
                                    "tor")
flows.add(journalist_to_securedrop)
journalist_replies = Dataflow.from_elements(tor_browser_journalist, hardware_firewall,
                              "tor")
flows.add(journalist_replies)
journalist_download = Dataflow.from_elements(tor_browser_journalist, encrypted_submission_in_journo,
                               "download")
flows.add(journalist_download)
traverse_airgap_online_side = Dataflow.from_elements(encrypted_submission_in_journo, transfer_device,
                                       "sneakernet")
flows.add(traverse_airgap_online_side)

# Data flows: in/to/from airgap area

traverse_airgap_offline_side = Dataflow.from_elements(transfer_device, encrypted_document, "sneakernet")
flows.add(traverse_airgap_offline_side)
decrypt_doc_1 = Dataflow.from_elements(encrypted_document, decryption, "gpg --decrypt")
flows.add(decrypt_doc_1)
decrypt_doc_2 = Dataflow.from_elements(decryption, decrypted_submission, "save plaintext")
flows.add(decrypt_doc_2)
sanitize_doc = Dataflow.from_elements(decrypted_submission, sanitization, "open in MAT")
flows.add(sanitize_doc)
clean_metadata = Dataflow.from_elements(sanitization, sanitized_document, "sanitize document")
flows.add(clean_metadata)
export_method_usb = Dataflow.from_elements(sanitized_document, export_device, "Export to USB")
flows.add(export_method_usb)
export_method_printer = Dataflow.from_elements(sanitized_document, printer, "Export via sending print job")
flows.add(export_method_printer)
print_docs = Dataflow.from_elements(printer, printed_documents, "Print")
flows.add(print_docs)

# Dataflows: Corporate workstation

transfer_to_corp_ws = Dataflow.from_elements(export_device, corp_workstation, "Export to USB")
flows.add(transfer_to_corp_ws)
journalist_processing_exports = Dataflow.from_elements(journalist, corp_workstation, "Processes submission")
flows.add(journalist_processing_exports)
journalist_uploads_cms = Dataflow.from_elements(corp_workstation, corp_cms, "Uploads to internal systems")
flows.add(journalist_uploads_cms)

# Data flows: in/to/from external services area

external_fpf_apt_app = Dataflow.from_elements(fpf_apt_repository, apt_client_app, "FPF apt updates (https, TCP/443)")
flows.add(external_fpf_apt_app)
external_fpf_apt_mon = Dataflow.from_elements(fpf_apt_repository, apt_client_mon, "FPF apt updates (https, TCP/443)")
flows.add(external_fpf_apt_mon)
external_ubuntu_apt_app = Dataflow.from_elements(ubuntu_apt_repository, apt_client_app, "Ubuntu apt updates (clearnet, TCP/80)")
flows.add(external_ubuntu_apt_app)
external_ubuntu_apt_mon = Dataflow.from_elements(ubuntu_apt_repository, apt_client_mon, "Ubuntu apt updates (clearnet, TCP/80)")
flows.add(external_ubuntu_apt_mon)
external_ntp_app = Dataflow.from_elements(ntp_server, ntp_client_app, "NTP (clearnet, UDP/123)")
flows.add(external_ntp_app)
external_ntp_mon = Dataflow.from_elements(ntp_server, ntp_client_mon, "NTP (clearnet, UDP/123)")
flows.add(external_ntp_mon)
external_smtp_app = Dataflow.from_elements(postfix, smtp_relay, "SMTP (clearnet TCP/25 or tls TCP/465)")
flows.add(external_smtp_app)
external_dns_app = Dataflow.from_elements(dns_server, dns_client_app, "DNS (clearnet, UDP/53)")
flows.add(external_dns_app)
external_dns_mon = Dataflow.from_elements(dns_server, dns_client_mon, "DNS (clearnet, UDP/53)")
flows.add(external_dns_mon)

# Data flows: in/to/from SecureDrop area

external_fpf_apt_app_firewall = Dataflow.from_elements(hardware_firewall, apt_client_app, "(https, TCP/443))")
flows.add(external_fpf_apt_app_firewall)
external_fpf_apt_mon_firewall = Dataflow.from_elements(hardware_firewall, apt_client_mon, "(https, TCP/443))")
flows.add(external_fpf_apt_mon_firewall)
external_ubuntu_apt_app_firewall = Dataflow.from_elements(hardware_firewall, apt_client_app, "(clearnet, TCP/80)")
flows.add(external_ubuntu_apt_app_firewall)
external_ubuntu_apt_mon_firewall = Dataflow.from_elements(hardware_firewall, apt_client_mon, "(clearnet, TCP/80)")
flows.add(external_ubuntu_apt_mon_firewall)
external_ntp_app_firewall = Dataflow.from_elements(hardware_firewall, ntp_client_app, "(clearnet, UDP/123)")
flows.add(external_ntp_app_firewall)
external_ntp_mon_firewall = Dataflow.from_elements(hardware_firewall, ntp_client_mon, "(clearnet, UDP/123)")
flows.add(external_ntp_mon_firewall)
external_smtp_app_firewall = Dataflow.from_elements(postfix, hardware_firewall, "(clearnet TCP/25 or tls TCP/465)")
flows.add(external_smtp_app_firewall)
external_dns_app_firewall = Dataflow.from_elements(hardware_firewall, dns_client_app, "(clearnet, UDP/53)")
flows.add(external_dns_app_firewall)
external_dns_mon_firewall = Dataflow.from_elements(hardware_firewall, dns_client_mon, "(clearnet, UDP/53)")
flows.add(external_dns_mon_firewall)
traffic_to_journalist_interface = Dataflow.from_elements(hardware_firewall, journalist_interface, "tor")
flows.add(traffic_to_journalist_interface)
traffic_to_source_interface = Dataflow.from_elements(hardware_firewall, source_interface, "tor")
flows.add(traffic_to_source_interface)
traffic_to_ssh_mon_interface = Dataflow.from_elements(hardware_firewall, ssh_mon_interface, "tor")
flows.add(traffic_to_ssh_mon_interface)
traffic_to_ssh_app_interface = Dataflow.from_elements(hardware_firewall, ssh_app_interface, "tor")
flows.add(traffic_to_ssh_app_interface)
proxied_local_ssh_app = Dataflow.from_elements(ssh_mon_interface, ssh_mon_daemon, "ssh, TCP/22")
flows.add(proxied_local_ssh_app)
proxied_local_ssh_mon = Dataflow.from_elements(ssh_app_interface, ssh_app_daemon, "ssh, TCP/22")
flows.add(proxied_local_ssh_mon)
tor_to_apache_ji = Dataflow.from_elements(journalist_interface, apache_web_server, "clearnet, TCP/8080")
flows.add(tor_to_apache_ji)
tor_to_apache_si = Dataflow.from_elements(source_interface, apache_web_server, "clearnet, TCP/80")
flows.add(tor_to_apache_si)
apache_to_app_code = Dataflow.from_elements(apache_web_server, securedrop_app, "WSGI")
flows.add(apache_to_app_code)

# Actually the SD app code should be another Boundary with these processes (e.g. gpg) inside

save_submissions = Dataflow.from_elements(securedrop_app, in_mem_submission, "save in memory")
flows.add(save_submissions)
crypto_operation = Dataflow.from_elements(in_mem_submission, asymmetric_encryption, "gpg --encrypt")
flows.add(crypto_operation)
save_ciphertext = Dataflow.from_elements(asymmetric_encryption, encrypted_submission, "save encrypted to disk")
flows.add(save_ciphertext)
app_database_save = Dataflow.from_elements(securedrop_app, app_database, "save data in relational db")
flows.add(app_database_save)
app_database_load = Dataflow.from_elements(app_database, securedrop_app, "load data from relational db")
flows.add(app_database_load)
ossec_communication = Dataflow.from_elements(ossec_agent, ossec_server, "OSSEC traffic (UDP/1515)")
flows.add(ossec_communication)
load_securedrop_config = Dataflow.from_elements(securedrop_app_config, securedrop_app, "load application config")
flows.add(load_securedrop_config)

for flow in flows:
    tm.add_element(flow)

# Trust boundaries
source_area = Boundary(
    "Source Area", 
    [source.identifier, tor_browser_source.identifier])
boundaries.append(source_area)

app_server = Boundary(
    "app server", 
    [journalist_interface.identifier, ssh_app_interface.identifier,ssh_app_daemon.identifier,
    securedrop_app.identifier, in_mem_submission.identifier, asymmetric_encryption.identifier,
    encrypted_submission.identifier, app_database.identifier, ossec_agent.identifier,
    apt_client_app.identifier, ntp_client_app.identifier, dns_client_app.identifier,
    securedrop_app_config.identifier, apache_web_server.identifier, source_interface.identifier
])
boundaries.append(app_server)

mon_server = Boundary(
    "mon server",
    [apt_client_mon.identifier, ntp_client_mon.identifier, dns_client_mon.identifier,
    postfix.identifier, ossec_server.identifier,
    ssh_mon_interface.identifier, ssh_mon_daemon.identifier])
boundaries.append(mon_server)

securedrop_area = Boundary("SecureDrop Area",
    [hardware_firewall.identifier, app_server.identifier, mon_server.identifier])
boundaries.append(securedrop_area)

external_services = Boundary(
    "External Services", 
    [fpf_apt_repository.identifier, ubuntu_apt_repository.identifier,
    ntp_server.identifier, smtp_relay.identifier, dns_server.identifier])
boundaries.append(external_services)

admin_workstation = Boundary(
    "Admin Workstation (Tails)", 
   [admin.identifier, ssh_admin.identifier, tor_admin.identifier])
boundaries.append(admin_workstation)

publishing_area = Boundary(
    "Publishing Area",
    [corp_workstation.identifier, corp_cms.identifier])
boundaries.append(publishing_area)
journalist_area = Boundary(
    "Journalist Workstation (Tails)", 
    [tor_browser_journalist.identifier, encrypted_submission_in_journo.identifier])
boundaries.append(journalist_area)
secure_viewing_station = Boundary(
    "Secure Viewing Station",
    [decryption.identifier, decrypted_submission.identifier, sanitization.identifier,
    sanitized_document.identifier])
boundaries.append(secure_viewing_station)
airgapped_area = Boundary(
    "Airgapped Viewing Area",
    [secure_viewing_station.identifier, encrypted_document.identifier, printer.identifier]
)
boundaries.append(airgapped_area)

for boundary in boundaries:
    tm.add_element(boundary)

tm.draw()
