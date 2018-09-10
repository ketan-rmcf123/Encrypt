%Reading the encrypted message from file Message.txt
fid = fopen("Message.txt","r");
s = fscanf(fid, "%s");
fclose(fid);
l = size(s,2);    %Calculates the length of input text.

%Generating the first key
for i = 1:127
  if(i<64)
    key1(i) = i+64;
  end
  if(i>64)
    key1(i) = i-64;
  end
  if(i==64)
    key1(i) = 64;
  end
end

%key1

%Generating the second key
for i=1:127
  key2(i) = 128-i;
end

%key2

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

%key3

%Input text is first decrypted by taking xor of corresponding elements of s and key3
for i=1:l
decrypted_2(i) = char(bitxor(key3(i),toascii(s(i))));
end

%Uncomment the next line to see the output after first encryption.
decrypted_2

%This decrypted message is now decrypted by taking xor of corresponding elemnts of decrypted_2 and key2.
for i=1:l
decrypted_1(i) = char(bitxor(key2(i),toascii(decrypted_2(i))));
end

%Uncomment the next line to see the output after second encryption.
decrypted_1

%The second decrypted message is decrypted by taking xor of corresponding elemnets of decrypted_1 and key1.
for i=1:l
output(i) = char(key1(toascii(decrypted_1(i))));
end

%Printing the final decrypted message to the terminal_size
output