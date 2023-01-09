import logging
import boto3
import json
import azure.functions as func
from botocore.exceptions import ClientError
from os import environ


def main(req: func.HttpRequest) -> func.HttpResponse:
    
    logging.info(f'Resource Requested: {func.HttpRequest}')

    # Get AWS ID and Key
    try:
        aws_access_key_id = environ['AWSAccessKeyID']
        aws_secret_access_key = environ['AWSSecretAccessKey']
        aws_region_name = environ['AWSRegionName']

    except KeyError as ke:
        logging.error(f'Invalid Settings. {ke.args} configuration is missing.')
        return func.HttpResponse(
             'Invalid Settings. AWS Access ID/Key configuration is missing.',
             status_code=500
        )

    # Get Query String from the request parameter
    query_string = req.params.get('QueryString')
    output_location = req.params.get('OutputLocation')
    database = req.params.get('Database')
    catalog = req.params.get('Catalog')

    if not (query_string and output_location and database and catalog):
        try:
            req_body = req.get_json()
        except ValueError:
            pass
        else:
            query_string = req_body.get('QueryString')
            output_location = req_body.get('OutputLocation')
            database = req_body.get('Database')
            catalog = req_body.get('Catalog')
    
    if query_string and output_location and database and catalog:
        
        try:
            logging.info(f'Creating Boto3 Athena Client.')
            athena_client = boto3.client(
                "athena",
                region_name=aws_region_name,
                aws_access_key_id=aws_access_key_id, 
                aws_secret_access_key=aws_secret_access_key
            )
            
            try:
                # Start the query execution
                logging.info(f'Sending Query Request.')
                response = athena_client.start_query_execution(
                    QueryString=query_string,
                    QueryExecutionContext={
                        "Database": database,
                        "Catalog": catalog
                    }, 
                    ResultConfiguration={"OutputLocation": output_location}
                )
                
                results = response['QueryExecutionId']
                return func.HttpResponse(
                    json.dumps(results),
                    headers = {"Content-Type": "application/json"},
                    status_code = 200
                )
        
            except athena_client.exceptions.InternalServerException as ex:
                logging.error(f"Internal Server Error: {str(ex)}")
                return func.HttpResponse("Internal Server Error", status_code=404)

            except athena_client.exceptions.InvalidRequestException as ex:
                logging.error(f"Invalid Request Exception: {str(ex)}")
                return func.HttpResponse(f"Invalid Request Exception: {str(ex)}", status_code=400)

            except athena_client.exceptions.TooManyRequestsException as ex:
                logging.error(f"Too Many Request Exception: {str(ex)}")
                return func.HttpResponse("Too Many Request Exception", status_code=400)

        except ClientError as ex:
            logging.error(f"Athena Client Error: {str(ex)}")
            return func.HttpResponse("Athena Client Error", status_code=401)
        
        except Exception as ex:
            logging.error(f"Exception Occured: {str(ex)}")
            return func.HttpResponse("Internal Server Exception", status_code=500)

    else:
        return func.HttpResponse(
             "Please pass QueryString, OutputLocation, Database, Catalog in the query string or request body.",
             status_code=400
        )
