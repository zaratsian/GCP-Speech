
import os
import html

from google.cloud import texttospeech

os.environ['GOOGLE_APPLICATION_CREDENTIALS'] = 'zproject201807-492e1131b782.json'


def ssml_to_audio(ssml_text):
    # Generates SSML text from plaintext.
    #
    # Given a string of SSML text and an output file name, this function
    # calls the Text-to-Speech API. The API returns a synthetic audio
    # version of the text, formatted according to the SSML commands. This
    # function saves the synthetic audio to the designated output file.
    #
    # Args:
    # ssml_text: string of SSML text
    # outfile: string name of file under which to save audio output
    #
    # Returns:
    # nothing
    
    # Instantiates a client
    client = texttospeech.TextToSpeechClient()
    
    # Sets the text input to be synthesized
    synthesis_input = texttospeech.types.SynthesisInput(ssml=ssml_text)
    
    # Builds the voice request, selects the language code ("en-US") and
    # the SSML voice gender ("MALE")
    voice = texttospeech.types.VoiceSelectionParams(
        language_code="en-US",
        ssml_gender=texttospeech.enums.SsmlVoiceGender.MALE
    )
    
    # Selects the type of audio file to return
    audio_config = texttospeech.types.AudioConfig(
        audio_encoding=texttospeech.enums.AudioEncoding.MP3
    )
    
    # Performs the text-to-speech request on the text input with the selected
    # voice parameters and audio file type
    response = client.synthesize_speech(synthesis_input, voice, audio_config)
    
    # The response's audio_content is binary.
    with open('/tmp/ssml_output.mp3', 'wb') as out:
        # Write the response to the output file.
        out.write(response.audio_content)
        print('Audio content written to file "/tmp/ssml_output.mp3"')



ssml_text = '''
<speak>
    CHAPTER ONE  <break time="3s"/> <break time="3s"/>
    
    Going in I recognized the scrawl. I eased the point of a knife blade into the flap and slit open the envelope. <break time="3s"/>
    
    It was the <say-as interpret-as="ordinal">1</say-as> letter at last from Babe Alsworth, the bush pilot.
    
    Come anytime. <prosody rate="slow" pitch="-2st">If we can’t land on the ice with wheels</prosody>, we can find some open water for floats. Typical Babe. Not a man to waste his words. \n This meant the end of my stay with Spike and Hope Carrithers at Sawmill Lake on Kodiak. I had driven my camper north and was doing odd jobs for them while waiting to hear from Babe. Their cabin in the Twin Lakes region had fired me up for the wilderness adventure I was about to go on. They seemed to sense my excitement and restlessness. I could use their cabin until I built one of my own. I could use their tools and was taking in more of my own. I also had the use of their Grumman canoe to travel up and down twelve miles of water as clear as a dewdrop. \n I left my camper in their care. I waved to them as I heard the engines begin to roar, and then the land moved faster and faster as I hurtled down the Kodiak strip on the flight to Anchorage.  Babe would meet me there. \n May 17, 1968 . At Merrill Field, while waiting for Babe to drop out of the sky in his 180 Cessna, I squinted at the Chugach Range, white and glistening in the sun, and I thought about the trip back north in the camper. It was always a good feeling to be heading north. In a Nebraska town I had bought a felt-tipped marker and on the back of my camper I printed in big letters, DESTINATION—BACK AND BEYOND. It was really surprising how many cars pulled up behind and stayed close for a minute or two even though the way was clear for passing. Then as they passed, a smile, a wave, or a wistful look that said more than words could. Westward to the Oregon ranch country and those high green places where I had worked in the 1940s. On to Seattle where a modern freeway led me through the city without a stop, and I thought of the grizzled old lumberjack who bragged that he had cut timber on First and Pike. Hard to imagine those tall virgin stands of Douglas fir and cedar and hemlock in place of cement, steel, and asphalt. Then the Cariboo Highway and beautiful British Columbia. Smack into a blizzard as I crossed Pine Pass on the John Hart Highway to Dawson Creek. And all those other places with their wonderful names: Muncho Lake and Teslin and Whitehorse, Kluane and Tok Junction, Matanuska and the Kenai. The ferry ride across the wild Gulf of Alaska and a red sun sinking into the rich blue of it. Sawmill Lake, and now Anchorage. \n The weather stayed clear, and Babe was on time. Same old Babe. Short in body and tall on experience. Wiry as a weasel. Sharp featured. Blue eyes that glinted from beneath eyebrows that tufted like feathers. A gray stubble of a moustache. That stocking cap perched atop his head. A real veteran of the bush. “Watches the weather,” his son-in-law once told me. “He knows the signs. If they’re not to his liking he’ll just sit by the fire and wait on better ones. That’s why he’s been around so long.” \n “Smooth through the pass,” Babe said. “A few things to pick up in town and we’re on our way.” \n We did the errands and returned to load our cargo aboard the  180. Babe got his clearance and off we went, Babe seeming to look over a hood that was too high for him. A banking turn over the outskirts of Anchorage, then we were droning over the mud flats of Cook Inlet on the 170 air-mile trip to Port Alsworth on Lake Clark. I looked down on the muskeg meadows pockmarked with puddles and invaded by stringy ranks of spruce. Now and then I glanced at Babe, whose eyes seemed transfixed on the entrance to Lake Clark Pass, his chin resting in one cupped hand. Meditating as usual. I searched the ground below for a moose, but we were too high to see enough detail. \n Suddenly the mountains hemmed us in on either side—steep wooded shoulders and ribs of rock falling away to the river that flowed to the south below, here and there a thin waterfall that appeared and disappeared in streamers of mist. We tossed in the air currents. Then we were above the big glacier, dirty with earth and boulders yet glinting blue from its shadowed crevices. It looked as though we were passing over the blades of huge, upturned axes, and then the land began to drop dizzily away beneath us and we were over the summit. The glacial river below was now flowing in a northerly direction through a dense forest of spruce, dividing now and then past slender islands of silt, and merging again in its rush to Lake Clark. \n There it was, a great silvery area in the darkness of the spruce—Lake Clark. We came in low over the water, heading for Tanalian Point and Babe’s place at Port Alsworth.
</speak>
'''





ssml_to_audio(ssml_text)



#ZEND