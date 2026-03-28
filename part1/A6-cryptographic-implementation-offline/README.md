Commands:

gpg --gen-key

<img width="429" height="97" alt="Screenshot 2026-03-28 at 10 48 06 AM" src="https://github.com/user-attachments/assets/cedc0b8f-daac-480f-a6db-93dd25344c37" />


echo "secret mnessage" > secret.txt


gpg --encrypt --armor --recipient 24252883@student.uwa.edu.au secret.txt

<img width="462" height="116" alt="Screenshot 2026-03-28 at 10 49 21 AM" src="https://github.com/user-attachments/assets/04012daf-a7c6-41fc-9b58-52fc6da38a97" />



gpg --decrypt secret.txt.asc

<img width="561" height="59" alt="Screenshot 2026-03-28 at 11 03 55 AM" src="https://github.com/user-attachments/assets/2bfac4e9-70bb-45f9-873f-653504e83ed8" />
