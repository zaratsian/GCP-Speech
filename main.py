
from flask import Flask, render_template, json, request, redirect, jsonify, url_for, session
import os,sys,re
import json
import requests
import datetime,time
import html
import six
import base64
from google.cloud import storage, bigquery
from google.cloud import texttospeech

#os.environ["GOOGLE_APPLICATION_CREDENTIALS"] = "/home/dzaratsian/creds.json"
os.environ['GOOGLE_APPLICATION_CREDENTIALS'] = 'zproject201807-492e1131b782.json'

############################################################
#
#   Variables
#
############################################################

project = 'zproject201807'

custom_dictionaries = {
    'Side Effects': [
        'ache', 'achiness', 'acne', 'agitated', 'anxiety', 'anxious', 'blurred vision', 'confusion', 'constipation', 'cramp', 'cramping', 'cramps', 
        'decreased sex drive', 'depression', 'diarrhea', 'difficulty having an orgasm', 'dizziness', 'dizzy', 'drowsiness', 
        'dry mouth', 'fatigue', 'fever', 'frequent urination', 'gaining weight', 'headache', 'headaches', 'heart palpitations', 
        'impotence', 'increase in appetite', 'insomnia', 'irritability', 'itch','itching','itches','joint pain', 'light headed-ness', 'light headedness', 
        'light-headed', 'light-headedness', 'lightheadedness', 'loss of appetite', 'loss of memory', 'loss of weight', 
        'low energy', 'memory loss', 'mood swing', 'mood swings', 'muscle pain', 'nausea', 'nauseous', 'nervous', 'nervousness', 
        'pain', 'painful', 'problem sleeping', 'rash', 'rashes', 'redness', 'restless', 'runny nose', 'seizure', 'seizures', 
        'sleep problems', 'sleepiness', 'sneezing', 'sore throat', 'spasm', 'spasms', 'stuffy nose', 'swell', 'swelled', 
        'swelling', 'swells', 'tired', 'tremor', 'tremors', 'trouble sleeping', 'upset stomach', 'vomit', 'vomiting', 'weakness', 
        'weight changes', 'weight gain', 'weight loss'
        ],
    'Medications':  [
        'altoprev', 'altoprev', 'amlodipine', 'antara', 'atorvastatin', 'atorvastatin', 'atorvastatinalirocumab', 
        'caduet', 'cholestyramine', 'colesevelam', 'colestid', 'colestipol', 'crestor', 'evolocumab', 'ezetimibe', 
        'ezetimibe-simvastatin', 'fenofibrate', 'fluvastatin', 'fluvastatin', 'gemfibrozil', 'icosapent ethyl', 'lescol', 
        'lescol xl', 'lescol xl', 'lipitor', 'lipofen', 'livalo', 'lopid', 'lovastatin', 'lovastatin', 'lovaza', 'mevacor', 
        'niacor', 'niaspan', 'pitavastatin', 'pitavastatin', 'praluent', 'pravachol', 'pravastatin', 'pravastatin', 
        'prevalite', 'repatha', 'rosuvastatin', 'rosuvastatin', 'simvastatin', 'simvastatin', 'vascepa', 'vytorin', 
        'welchol', 'zetia', 'zocor'
        ]
}


custom_regexes = {
    "Dosage": "[0-9\.]+[ ]*(milligram|milligrams|mg|mG|Millilitre|millilitres|ml|ML|teaspoons|teaspoon|tsp|tsps|tablespoon|tablespoons|Tbsp|Tbsps|Tb|Tbs|litre|litres|L|fluid ounce|fl oz|micrograms|microgram|mcg|mcgs|grams|gram|gm|ounces|Ounce|oz)"
}



############################################################
#
#   Flask App
#
############################################################


app = Flask(__name__)
app.secret_key = os.urandom(24)


############################################################
#
#   Functions
#
############################################################


def bq_query(query, location='US'):
    '''
        Query BigQuery Table(s)
        
        location: US, EU, asia-northeast1 (Tokyo), europe-west2 (London), asia-southeast1 (Singapore), australia-southeast1 (Sydney)
        
    '''
    try:
        client = bigquery.Client()
        
        query_job = client.query(query, location=location)
        
        rows = []
        for i, row in enumerate(query_job):
            rows.append(row)
        
        print('[ INFO ] Query returned {} row(s)'.format( len(rows) ))
        return rows
    except Exception as e:
        print('[ ERROR] {}'.format(e))



def inspect_string(project, text_blob,
                   custom_dictionaries=None, custom_regexes=None,
                   min_likelihood=None, max_findings=None, include_quote=True):
    """Uses the Data Loss Prevention API to analyze strings for protected data.
    Args:
        project: The Google Cloud project id to use as a parent resource.
        text_blob: The string to inspect.
        info_types: A list of strings representing info types to look for.
            A full list of info type categories can be fetched from the API.
        min_likelihood: A string representing the minimum likelihood threshold
            that constitutes a match. One of: 'LIKELIHOOD_UNSPECIFIED',
            'VERY_UNLIKELY', 'UNLIKELY', 'POSSIBLE', 'LIKELY', 'VERY_LIKELY'.
        max_findings: The maximum number of findings to report; 0 = no maximum.
        include_quote: Boolean for whether to display a quote of the detected
            information in the results.
        custom_dictionaries = {'numbers':'one,two,three', 'names':'dan,amber'}
    Returns:
        None; the response from the API is printed to the terminal.
    """
    # Import the client library
    #import google.cloud.dlp
    
    # Instantiate a client.
    dlp = google.cloud.dlp.DlpServiceClient()
    
    # Prepare info_types by converting the list of strings into a list of
    # dictionaries (protos are also accepted).
    info_types      = [ 'AGE','ALL_BASIC','CREDIT_CARD_NUMBER','DATE','DATE_OF_BIRTH','DOMAIN_NAME','EMAIL_ADDRESS',
                    'ETHNIC_GROUP','FEMALE_NAME','FIRST_NAME','GCP_CREDENTIALS','GENDER','IBAN_CODE','ICD9_CODE',
                    'ICD9_CODE','ICD10_CODE','IMEI_HARDWARE_ID','IP_ADDRESS','LAST_NAME','LOCATION','MAC_ADDRESS',
                    'MAC_ADDRESS_LOCAL','MALE_NAME','PERSON_NAME','PHONE_NUMBER','SWIFT_CODE','TIME','URL',
                    'AMERICAN_BANKERS_CUSIP_ID','FDA_CODE','US_ADOPTION_TAXPAYER_IDENTIFICATION_NUMBER','US_BANK_ROUTING_MICR',
                    'US_DEA_NUMBER','US_DRIVERS_LICENSE_NUMBER','US_EMPLOYER_IDENTIFICATION_NUMBER','US_HEALTHCARE_NPI',
                    'US_INDIVIDUAL_TAXPAYER_IDENTIFICATION_NUMBER','US_PASSPORT','US_PREPARER_TAXPAYER_IDENTIFICATION_NUMBER',
                    'US_SOCIAL_SECURITY_NUMBER','US_STATE','US_TOLLFREE_PHONE_NUMBER','US_VEHICLE_IDENTIFICATION_NUMBER'
                    ]
    
    info_types = [{'name': info_type} for info_type in info_types]
    
    # Prepare custom_info_types by parsing the dictionary word lists and
    # regex patterns.
    if custom_dictionaries != None:
        dictionaries = [{
            'info_type': {'name': '{}'.format( k )},
            'dictionary': {
                'word_list': { 'words': v }
            }
        } for k,v in custom_dictionaries.items()]   
    else:
        dictionaries = []
    
    if custom_regexes != None:
        regexes = [{
            'info_type': {'name': '{}'.format( k )},
            'regex': {'pattern': custom_regex}
        } for k, custom_regex in custom_regexes.items()]
    else:
        regexes = []
    
    custom_info_types = dictionaries + regexes  # custom_info_types = []
    
    # Construct the configuration dictionary. Keys which are None may
    # optionally be omitted entirely.
    inspect_config = {
        'info_types': info_types,
        'custom_info_types': custom_info_types,
        'min_likelihood': min_likelihood,
        'include_quote': include_quote,
        'limits': {'max_findings_per_request': max_findings},
    }
    
    # Construct the `item`.
    item = {'value': text_blob}
    
    # Convert the project id into a full resource id.
    parent = dlp.project_path(project)
    
    # Call the API.
    response = dlp.inspect_content(parent, inspect_config, item)
    
    # Format String Output
    formatted_findings = {}
    for finding in response.result.findings:
        info_type  = finding.info_type.name
        info_match = finding.quote
        if info_type not in formatted_findings:
            formatted_findings[info_type] = [info_match]
        else:
            formatted_findings[info_type] += [info_match]
    '''
    findings_output = ''
    for key,val in formatted_findings.items():
        findings_output = findings_output + '{}:\n'.format(key)
        for v in val:
            findings_output = findings_output + '\t{}\n'.format(v)
    '''
    return response, formatted_findings



def deidentify_with_mask(project, text_blob, masking_character=None, number_to_mask=0):
    """Uses the Data Loss Prevention API to deidentify sensitive data in a
    text_blob by masking it with a character.
    Args:
        project: The Google Cloud project id to use as a parent resource.
        item: The text_blob to deidentify (will be treated as text).
        masking_character: The character to mask matching sensitive data with.
        number_to_mask: The maximum number of sensitive characters to mask in
            a match. If omitted or set to zero, the API will default to no
            maximum.
    Returns:
        None; the response from the API is printed to the terminal.
    """
    # Import the client library
    #import google.cloud.dlp
    
    # Instantiate a client
    dlp = google.cloud.dlp.DlpServiceClient()
    
    # Convert the project id into a full resource id.
    parent = dlp.project_path(project)
    
    # Construct inspect configuration dictionary
    info_types      = [ 'AGE','ALL_BASIC','CREDIT_CARD_NUMBER','DATE','DATE_OF_BIRTH','DOMAIN_NAME','EMAIL_ADDRESS',
                    'ETHNIC_GROUP','FEMALE_NAME','FIRST_NAME','GCP_CREDENTIALS','GENDER','IBAN_CODE','ICD9_CODE',
                    'ICD9_CODE','ICD10_CODE','IMEI_HARDWARE_ID','IP_ADDRESS','LAST_NAME','LOCATION','MAC_ADDRESS',
                    'MAC_ADDRESS_LOCAL','MALE_NAME','PERSON_NAME','PHONE_NUMBER','SWIFT_CODE','TIME','URL',
                    'AMERICAN_BANKERS_CUSIP_ID','FDA_CODE','US_ADOPTION_TAXPAYER_IDENTIFICATION_NUMBER','US_BANK_ROUTING_MICR',
                    'US_DEA_NUMBER','US_DRIVERS_LICENSE_NUMBER','US_EMPLOYER_IDENTIFICATION_NUMBER','US_HEALTHCARE_NPI',
                    'US_INDIVIDUAL_TAXPAYER_IDENTIFICATION_NUMBER','US_PASSPORT','US_PREPARER_TAXPAYER_IDENTIFICATION_NUMBER',
                    'US_SOCIAL_SECURITY_NUMBER','US_STATE','US_TOLLFREE_PHONE_NUMBER','US_VEHICLE_IDENTIFICATION_NUMBER'
                    ]
    
    inspect_config = {
        'info_types': [{'name': info_type} for info_type in info_types]
    }
    
    # Construct deidentify configuration dictionary
    deidentify_config = {
        'info_type_transformations': {
            'transformations': [
                {
                    'primitive_transformation': {
                        'character_mask_config': {
                            'masking_character': masking_character,
                            'number_to_mask': number_to_mask
                        }
                    }
                }
            ]
        }
    }
    
    # Construct item
    item = {'value': text_blob}
    
    # Call the API
    response = dlp.deidentify_content(
        parent, inspect_config=inspect_config,
        deidentify_config=deidentify_config, item=item)
    
    # Print out the results.
    return response.item.value



def get_prediction(content, project_id, model_id):
    prediction_client = automl_v1beta1.PredictionServiceClient()    
    name = 'projects/{}/locations/us-central1/models/{}'.format(project_id, model_id)
    payload = {'image': {'image_bytes': content }}
    params = {'score_threshold':'0.04'}
    request = prediction_client.predict(name, payload, params)
    return request  # waits till request is returned


def gcp_text_to_speech(text, gender='neutral', language='en-US', standard_or_wavenet='wavenet' ):
    # Instantiates a client
    client = texttospeech.TextToSpeechClient()
    
    language_key = '{}-{}-{}'.format(language, standard_or_wavenet.title(), gender.lower())
    language_key_map = {
        'en-AU-Wavenet-female': 'en-AU-Wavenet-A',
        'en-AU-Wavenet-male':   'en-AU-Wavenet-B',
        'en-IN-Wavenet-female': 'en-IN-Wavenet-A',
        'en-IN-Wavenet-male':   'en-IN-Wavenet-B',
        'en-GB-Wavenet-female': 'en-GB-Wavenet-A',
        'en-GB-Wavenet-male':   'en-GB-Wavenet-B',
        'en-US-Wavenet-female': 'en-US-Wavenet-C',
        'en-US-Wavenet-male':   'en-US-Wavenet-B',
    }
    
    ssml_gender_map = {
        'neural':   texttospeech.enums.SsmlVoiceGender.NEUTRAL,
        'male':     texttospeech.enums.SsmlVoiceGender.MALE,
        'female':   texttospeech.enums.SsmlVoiceGender.FEMALE
    }
    
    # Set the text input to be synthesized
    synthesis_input = texttospeech.types.SynthesisInput(text=text)
    
    # Build the voice request, select the language code ("en-US") and the ssml
    # voice gender ("neutral")
    print('[ INFO ] {} {}'.format(language, language_key ))
    voice = texttospeech.types.VoiceSelectionParams(
        language_code=  language,
        name=           language_key_map[language_key]) #,
        #ssml_gender=    ssml_gender_map[gender])
    
    # Select the type of audio file you want returned
    audio_config = texttospeech.types.AudioConfig(audio_encoding=texttospeech.enums.AudioEncoding.MP3)
    
    # Perform the text-to-speech request on the text input with the selected
    # voice parameters and audio file type
    response = client.synthesize_speech(synthesis_input, voice, audio_config)
    
    '''
    # The response's audio_content is binary.
    with open('/tmp/output.mp3', 'wb') as out:
        # Write the response to the output file.
        out.write(response.audio_content)
        print('Audio content written to file "/tmp/output.mp3"')
    '''
    return response.audio_content


def gcp_storage_upload_string(source_string, bucket_name, blob_name):
    '''
        Google Cloud Storage - Upload Blob from String
    '''
    try:
        storage_client = storage.Client()
        bucket = storage_client.get_bucket(bucket_name)
        blob = bucket.blob(blob_name)
        blob.upload_from_string(source_string)
    except Exception as e:
        print('[ ERROR ] {}'.format(e))




blacklist = [   '[document]',   'noscript', 'header',   'html', 'meta', 'head','input', 'script',   ]


def epub2thtml(epub_path):
    book = epub.read_epub(epub_path)
    chapters = []
    for item in book.get_items():
        if item.get_type() == ebooklib.ITEM_DOCUMENT:
            chapters.append(item.get_content())
    return chapters


def chap2text(chap):
    output = ''
    soup = BeautifulSoup(chap, 'html.parser')
    text = soup.find_all(text=True)
    for t in text:
        if t.parent.name not in blacklist:
            output += '{} '.format(t)
    return output


def thtml2ttext(thtml):
    Output = []
    for html in thtml:
        text =  chap2text(html)
        Output.append(text)
    return Output


def epub2text(epub_path):
    chapters = epub2thtml(epub_path)
    ttext = thtml2ttext(chapters)
    return ttext



############################################################
#
#   Home
#
############################################################
@app.route('/', methods = ['GET','POST'])
def tts():
    try:
        user = request.headers['X-Goog-Authenticated-User-Email'].split(':')[-1]
    except:
        user = 'dzaratsian@google.com'
    
    datetimestamp = str(datetime.datetime.now())
    
    if request.method == 'GET':
        text = '''
Nicolo Machiavelli was born at Florence on 3rd May 1469. He was the
second son of Bernardo di Nicolo Machiavelli, a lawyer of some repute,
and of Bartolommea di Stefano Nelli, his wife. Both parents were members
of the old Florentine nobility.

His life falls naturally into three periods, each of which singularly
enough constitutes a distinct and important era in the history of
Florence. His youth was concurrent with the greatness of Florence as an
Italian power under the guidance of Lorenzo de' Medici, Il Magnifico.
The downfall of the Medici in Florence occurred in 1494, in which year
Machiavelli entered the public service. During his official career
Florence was free under the government of a Republic, which lasted
until 1512, when the Medici returned to power, and Machiavelli lost his
office. The Medici again ruled Florence from 1512 until 1527, when they
were once more driven out. This was the period of Machiavelli's literary
activity and increasing influence; but he died, within a few weeks of
the expulsion of the Medici, on 22nd June 1527, in his fifty-eighth
year, without having regained office.
        '''
        return render_template('tts.html', user=user, text=text, language='en-US', gender='female')
    
    if request.method == 'POST':
        text_blob = request.form['text']
        language  = request.form['language']
        gender    = request.form['gender']
        
        audio_content = gcp_text_to_speech(text=text_blob, gender=gender, language=language, standard_or_wavenet='wavenet' )
        gcp_storage_upload_string(audio_content, bucket_name='z-speech-audio-files', blob_name='tts_output.mp3')
        return render_template('tts.html', user=user, text=text_blob, language=language, gender=gender)


############################################################
#
#   DialogFlow
#
############################################################
@app.route('/dialog', methods = ['GET','POST'])
def dialog():
    try:
        user = request.headers['X-Goog-Authenticated-User-Email'].split(':')[-1]
    except:
        user = 'dzaratsian@google.com'
    
    datetimestamp = str(datetime.datetime.now())
    
    if request.method == 'GET':
        return render_template('dialog.html', user=user)



############################################################
#
#   eBook Processing
#
############################################################
@app.route('/dropzone', methods = ['GET','POST'])
def dropzone():
    
    try:
        user = request.headers['X-Goog-Authenticated-User-Email'].split(':')[-1]
    except:
        user = 'dzaratsian@google.com'
    datetimestamp = str(datetime.datetime.now())
    
    if request.method == 'GET':
        return render_template('dropzone.html', user=user)
    
    elif request.method == 'POST':
        
        img = request.files['image']
        print('[zinfo] {}'.format(type(img)))
        print('[zinfo] {}'.format(str(img)))
        
        return render_template('dropzone.html', user=user, img=img_out, prediction=prediction)




############################################################
#
#   Run App
#
############################################################
if __name__ == "__main__":
    #app.run(debug=True, threaded=True, host='0.0.0.0', port=5555)
    app.run(debug=True, threaded=False, host='0.0.0.0', port=8080)



#ZEND
