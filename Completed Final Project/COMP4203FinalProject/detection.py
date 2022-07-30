import pyshark

firstPacket = True

#Counts how many consecutive attack frames have been flagged
attackFramesCounted = 0

#Number of consecutive attack frames that must be flagged to signal a Deauthentication attack
attackFramesThreshold = 5

#The max amount of time allowed between consecutive timestamps
timeStampThreshold = 0.2

deauthSubtype = '0x000c'

#Filter for Live Capture. Please enter the appropriate MAC address.
#How to use: 'wlan.da' for destination MAC address and 'wlan.sa' for source MAC address
#Currently set to filter for packets destined for Access Point MAC address
filter = 'wlan.da == 08:a7:c0:a1:0a:da'

#Message for user to know the attack detection has begun detecting
print("Waiting For Attack...")

capture = pyshark.LiveCapture(interface='wlan0', display_filter=filter)
for packet in capture.sniff_continuously():

	#Checks the frame for Type/Subtype: "Deauthentication" (aka. '0x000c')
	if(packet[2].fc_type_subtype == deauthSubtype):
		if(firstPacket):
			reasonCode = packet[3].wlan_fixed_reason_code
			previousTimeStamp = packet.sniff_timestamp 
			firstPacket = False
		else:
			currentReasonCode = packet[3].wlan_fixed_reason_code
			currentTimeStamp = packet.sniff_timestamp
			timeStampDifference = float(currentTimeStamp) - float(previousTimeStamp)
			if(timeStampDifference < timeStampThreshold):
				if(currentReasonCode == reasonCode):
					attackFramesCounted+=1
					if(attackFramesCounted == attackFramesThreshold):
						print("Experiencing a De-authentication Attack!!!")
						attackFramesCounted = 0
			previousTimeStamp = currentTimeStamp
			reasonCode = currentReasonCode
