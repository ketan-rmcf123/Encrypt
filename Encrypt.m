%This program encrypts the given text message using 3DES method.
%In this method, the input text is encrypted through three different keys one by one.
%This program takes input text from the user through the terminal.
%After encryption, the final message is saved in "Message.txt" file.

clc
clear

s = input("Enter your text message : ","s");
disp("Message Received");
l=length(s);    %Calculating length of input signal

%Generating the first key
for i=1:127
  if(i<64)
    key1(i)=i+64;
  end
  if(i>64)
    key1(i) = i-64;
  end
  if(i==64)
    key1(i)=64;
  end
end

key1

%Generating the second key
for i=1:127
  key2(i) = 128-i;
end

key2

%Generating the third key
for i=1:126
  if(mod(i,2)==1)
    key3(i) = i+1;
  end
  if(mod(i,2)==0)
    key3(i) = i-1;
  end
end
key3(127) = 127;

key3

%Encrypting the first message using key1
for i=1:l
  encrypted_1(i) = char(key1(toascii(s(i))));
end

%Uncomment the next line to see first encrypted message
encrypted_1

%Encrypting the first encrypted message using key2
for i=1:l
  encrypted_2(i) = char(bitxor(toascii(encrypted_1(i)), key2(i)));
end

%Uncomment the next line to see second encrypted message
encrypted_2

%Encrypting the second encrypted message using key3
for i=1:l
  final(i) = char( bitxor( toascii(encrypted_2(i)), key3(i)) );
end

%Uncomment the next line to see final encrypted message
final

%Writing the final output in a file "Message.txt"
fid = fopen("Message.txt","w");
fprintf(fid, "%s", final);
fclose(fid);

disp("Your message was successfully stored in 'Message.txt' file");