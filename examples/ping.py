from SiemplifyUtils import output_handler
from SiemplifyAction import SiemplifyAction
from IPInfoManager import IPInfoManager

ACTION_NAME = "IPInfo Ping"
PROVIDER = 'IPInfo'


@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = ACTION_NAME
    conf = siemplify.get_configuration(PROVIDER)
    output_message = "Connection Established"
    verify_ssl = conf.get('Verify SSL', 'false').lower() == 'true'
    ipinfo_manager = IPInfoManager(conf['API Root'], conf['Token'], verify_ssl)
    ping_status = ipinfo_manager.ping()
    if !ping_status:
      output_message = "Failed to connect."
    siemplify.end(output_message, ping_status)


if __name__ == "__main__":
    main()

