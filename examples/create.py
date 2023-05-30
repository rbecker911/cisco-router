from SiemplifyUtils import output_handler
from SiemplifyAction import SiemplifyAction
from ZendeskManager import ZendeskManager
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED
from TIPCommon import extract_configuration_param, extract_action_param
INTEGRATION_NAME = u"Zendesk"
CREATE_TICKET = u"Create Ticket"
@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = CREATE_TICKET
    siemplify.LOGGER.info(u"----------------- Main - Param Init -----------------")
    # Integration Configuration    
    api_token = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME,
                                                  param_name=u"Api Token", print_value=False, is_mandatory=True)
    server_address = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME,
                                                  param_name=u"Server Address", is_mandatory=True, print_value=True)
    # Action Configuration 
    subject = extract_action_param(siemplify, param_name=u"Subject", is_mandatory=True, print_value=True, input_type=unicode)
    description = extract_action_param(siemplify, param_name=u"Description", is_mandatory=True, print_value=True, input_type=unicode)
    assigned_user = extract_action_param(siemplify, param_name=u"Assigned User", is_mandatory=False, print_value=True, input_type=unicode)
    
    siemplify.LOGGER.info(u"----------------- Main - Started -----------------")    
    status = EXECUTION_STATE_COMPLETED
    result_value = True
     
    try:
        zendesk = ZendeskManager(api_token, server_address)
        new_ticket = zendesk.create_ticket(subject=subject, description=description, assigned_to=assigned_user)
        if new_ticket:
            ticket_id = new_ticket['ticket']['id']
            output_message = u"Successfully created ticket with id: {0}".format(str(ticket_id))
            result_value = ticket_id
        else:
            output_message = u'There was a problem creating ticket.'
            result_value = False
            
    except Exception as e:
        output_message = u'Error executing action {}. Reason: {}'.format(CREATE_TICKET, e)
        siemplify.LOGGER.error(output_message)
        siemplify.LOGGER.exception(e)
        status = EXECUTION_STATE_FAILED
        result_value = False
    siemplify.LOGGER.info(u'----------------- Main - Finished -----------------')
    siemplify.LOGGER.info(
        u'\n  status: {}\n  result_value: {}\n  output_message: {}'.format(status, result_value, output_message))
    siemplify.end(output_message, result_value, status)
if __name__ == '__main__':
    main()
