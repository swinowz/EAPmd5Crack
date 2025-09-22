# EAPmd5Crack
Just a simple scrpt that I had to use for a challenge in an event 

To use this tool, simply gather necessary arguments and run the script with : eap_id, challenge, response, wordlist
```
tshark -r FILE.cap -Y "eap.type == 4" -T fields -e frame.number -e eap.code -e eap.id -e eap.md5.value
```
<img width="465" height="293" alt="image" src="https://github.com/user-attachments/assets/b5585e5f-6e07-412b-b860-cacd1218d035" />
```
python3 EAPmd5Crack.py 69 2f10a081f77146d3f140750b9ded23bc d08b86f49f380e5aac9cc6ba5b374e61 wordlist 
```
(censored since it's for an active challenge)
<img width="518" height="369" alt="image" src="https://github.com/user-attachments/assets/8c74f75d-739a-4a9d-bb15-613ffbb64607" />
