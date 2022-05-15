from azure.cognitiveservices.vision.computervision import ComputerVisionClient
from azure.cognitiveservices.vision.computervision.models import OperationStatusCodes
from azure.cognitiveservices.vision.computervision.models import VisualFeatureTypes
from msrest.authentication import CognitiveServicesCredentials
import time

from solver import solver

ILLEGAL_CHARACTERS = ["@", "%", ":", "£", '"', "&", "!", "_", "|", "`", "¬", "¦", "<", ">", "'"]

class Azure_OCR():
    def __init__(self, subscription_key, endpoint):
        self.computervision_client = None
        self.authenticate(subscription_key, endpoint)

    def authenticate(self, subscription_key, endpoint):
        self.computervision_client = ComputerVisionClient(endpoint, CognitiveServicesCredentials(subscription_key))

    def read_equations(self, image_path):
        results = []

        if self.computervision_client == None:
            raise Exception("Must authenicate first using authenticate(subcription_key, endpoint)")
        
        image = open(image_path, 'rb')
        read_response = self.computervision_client.read_in_stream(image, raw=True)

        # Get the operation location (URL with an ID at the end) from the response
        read_operation_location = read_response.headers["Operation-Location"]
        # Grab the ID from the URL
        operation_id = read_operation_location.split("/")[-1]

        # Call the "GET" API and wait for it to retrieve the results 
        while True:
            read_result = self.computervision_client.get_read_result(operation_id)
            if read_result.status not in ['notStarted', 'running']:
                break
            time.sleep(1)

        if read_result.status == OperationStatusCodes.succeeded:
            for text_result in read_result.analyze_result.read_results:
                for line in text_result.lines:
                    #print(line.text)
                    #print(line.bounding_box)
                    
                    text = line.text
                    equation = text

                    if any(char.isdigit() for char in text) & any(not char.isalnum() for char in text):
                        if ". " in text:
                            text = equation.split(".")[1]

                        if text[-1] == ".":
                            equation=None

                        if any(char in ILLEGAL_CHARACTERS for char in text):
                            equation=None
                        
                        #if ((sum(char.isdigit() for char in text) + sum(char.isalnum() for char in text) - sum(char == " " for char in text)) / (len(text) - sum(char == " " for char in text)) < 0.8):
                        #   equation=None;

                        if equation != None:
                            results.append(text)

        return results