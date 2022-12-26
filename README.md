# DNS cache poisoning
## notes: 
  * the poisoning tool is waiting for an active query from any client that using in the dns server - (to be efficent - if the name is already in the cache) 
  * run the script as sudo 
  * shut down the ip forwarding 
  
 ## dns server building : 
  * `sudo apt-get update`
  * `sudo apt install bind9`
  * `sudo nano /etc/bind/named.conf.options`
    
    change to those settings : 
    `//dnssec-validation auto;
      dnssec-enable: no;
      send-cookie no;
      answer-cookie no`
   * `sudo service named start`
   * check the status of the server to check out the setup : `sudo service named status`
   
   to re-config : 
   * `sudo rndc reconfig`
   
   to clear the dns server cache: 
   * `sudo rndc flush`
      
# example:
I changed "youtube.com" address to my kali vm address in the dns cache  and then tried to connect from another machine which it's default dns server is the corrupted dns server 

<img width="401" alt="Screenshot 2022-12-26 at 21 16 03" src="https://user-images.githubusercontent.com/90776557/209577871-3a5de361-4114-4f6f-865b-6962d7b1fc54.png">
<img width="568" alt="Screenshot 2022-12-26 at 21 16 32" src="https://user-images.githubusercontent.com/90776557/209577874-b7deba34-f0e9-4e78-813c-5071d02f1c0b.png">
<img width="373" alt="Screenshot 2022-12-26 at 21 15 56" src="https://user-images.githubusercontent.com/90776557/209577882-f06dad30-91c7-4ce7-b5df-b171ccaa9014.png">
<img width="648" alt="Screenshot 2022-12-26 at 21 15 31" src="https://user-images.githubusercontent.com/90776557/209577889-567a878a-1154-427c-b308-a059bc7ce748.png">
<img width="330" alt="Screenshot 2022-12-26 at 21 15 27" src="https://user-images.githubusercontent.com/90776557/209577891-663f043a-9752-4b70-a18d-21b741d1b9c4.png">

by : Idan.M
