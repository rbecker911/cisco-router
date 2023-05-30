from TIPCommon import (
    extract_configuration_param,
    extract_action_param,
    convert_comma_separated_to_list,
    convert_list_to_comma_string,
    construct_csv
)
from ZohoDeskManager import ZohoDeskManager
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED
from SiemplifyAction import SiemplifyAction
from SiemplifyUtils import output_handler

TABLE_NAME = 'Ticket Details'


@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = GET_TICKET_DETAILS_SCRIPT_NAME
    siemplify.LOGGER.info("----------------- Main - Param Init -----------------")

    api_root = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name="API Root",
                                           is_mandatory=True, print_value=True)
    client_id = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name="Client ID",
                                            is_mandatory=True, print_value=True)
    client_secret = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name="Client Secret",
                                                is_mandatory=True, remove_whitespaces=False)
    refresh_token = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name="Refresh Token",
                                                is_mandatory=False, remove_whitespaces=False)
    verify_ssl = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name="Verify SSL",
                                             is_mandatory=True, input_type=bool, print_value=True)

    # Action configuration
    ticket_ids = extract_action_param(siemplify, param_name="Ticket IDs", is_mandatory=True, print_value=True)
    create_insight = extract_action_param(siemplify, param_name="Create Insight", print_value=True, input_type=bool)
    additional_fields = extract_action_param(siemplify, param_name="Additional Fields To Return", print_value=True)
    fetch_comments = extract_action_param(siemplify, param_name="Fetch Comments", print_value=True, input_type=bool)

    siemplify.LOGGER.info("----------------- Main - Started -----------------")
    ticket_ids = convert_comma_separated_to_list(ticket_ids)
    result_value = True
    status = EXECUTION_STATE_COMPLETED
    output_message = ""
    successful_tickets, failed_ticket_ids, json_results = [], [], []

    try:

        manager = ZohoDeskManager(api_root=api_root, client_id=client_id, client_secret=client_secret,
                                  refresh_token=refresh_token, verify_ssl=verify_ssl, siemplify_logger=siemplify.LOGGER)
        for ticket_id in ticket_ids:
            siemplify.LOGGER.info(f"Started processing ticket: {ticket_id}")
            try:
                ticket = manager.get_ticket(
                    ticket_id=ticket_id,
                    additional_fields=convert_list_to_comma_string(additional_fields).replace(' ', '').replace(
                        'isread', 'isRead') if additional_fields else ""
                )

                ticket_json = ticket.to_json()
                if fetch_comments:
                    ticket_json["comments"] = [comment.to_json() for comment in
                                               manager.get_ticket_comments(ticket_id, fetch_limit)]
                successful_tickets.append(ticket)
                json_results.append(ticket_json)

            except Exception as e:
                siemplify.LOGGER.error(f"Failed processing ticket: {ticket_id}: Error is: {e}")
                failed_ticket_ids.append(ticket_id)


        if successful_tickets:
            siemplify.result.add_result_json(json_results)
            siemplify.result.add_data_table(TABLE_NAME, construct_csv([ticket.to_table() for ticket in
                                                                       successful_tickets]))

            if create_insight:
                for ticket in successful_tickets:
                    siemplify.create_case_insight(triggered_by=INTEGRATION_NAME,
                                                  title=f"Ticket {ticket.id}",
                                                  content=ticket.to_insight(),
                                                  entity_identifier="",
                                                  severity=InsightSeverity.INFO,
                                                  insight_type=InsightType.General)

            output_message += f"Successfully returned details related to the following tickets in " \
                              f"{INTEGRATION_DISPLAY_NAME}: " \
                              f"\n{', '.join([ticket.id for ticket in successful_tickets])}.\n\n"

            if failed_ticket_ids:
                output_message += f"Action wasn't able to find details related to the following tickets in " \
                                  f"{INTEGRATION_DISPLAY_NAME}: {', '.join(failed_ticket_ids)}.\n"
        else:
            output_message = "No tickets were found."
            result_value = False

    except Exception as error:
        output_message = f'Error executing action {GET_TICKET_DETAILS_SCRIPT_NAME}. Reason: {error}'
        siemplify.LOGGER.error(output_message)
        siemplify.LOGGER.exception(error)
        status = EXECUTION_STATE_FAILED
        result_value = False

    siemplify.end(output_message, result_value, status)


if __name__ == '__main__':
    main()

