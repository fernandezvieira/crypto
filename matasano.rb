#!/usr/bin/ruby

require 'base64'
require 'openssl'

normalized_frequency = nil

def print_starting(number)
  puts "Challenge #{number} starting"
end

def print_result(bool, challenge)
  to_print = bool ? "Challenge #{challenge} passed" : "Challenge #{challenge} failed"
  puts to_print
end

def hex_to_base64(str)
  [[str].pack("H*")].pack("m0")
end

def xor_bytes(bytes, bytes_2)
  bytes.zip(bytes_2).map { |l,r| l^r }
end

def xor_str(str1, str2)
  xor_bytes(str1.bytes, str2.bytes)
end

def xor(bytes, single_byte)
  bytes.map {|x| x ^ single_byte}
end

def repeating_key_xor(string, repeating_key)
  xor_bytes(string.bytes, repeating_key.bytes.cycle)
end

def repeating_key_xor_bytes(bytes, repeating_bytes)
  xor_bytes(bytes, repeating_bytes.cycle)
end

def freq(file)
  if @normalized_frequency.nil?
    text = File.read(file)
    text = text.upcase
    text = text.gsub(/\n/, ' ')
    text = text.gsub(/ +/, ' ')
    @normalized_frequency = normalized_freq(text.bytes)
  end

  @normalized_frequency
end

def normalized_freq(bytes)
  normalize(byte_freq(bytes))
end

def normalize(freq)
  total = freq.reduce(0) {|acc, e| acc + e}
  freq.map {|x| x / total.to_f}
end

def byte_freq(bytes)
  vector = [0] * 256
  bytes.each do |x|
    vector[x] = vector[x] + 1
  end
  vector
end

def unhex(hex)
  hex.scan(/../).map {|x| x.to_i(16)}
end

def score(actual, expected)
  distance(normalized_freq(actual.pack("c*").upcase.bytes), expected)
end

def distance(l, r)
  l.zip(r).reduce(0) do |acc, e|
    diff = (e[0] - e[1])
    acc + diff * diff
  end
end

def hamming_distance(bytes, bytes_2)
  xord = xor_bytes(bytes, bytes_2)

  xord.inject(0) {|sum, x| sum += x.to_s(2).count("1"); sum }
end

def challenge_1
  print_starting(1)

  result = hex_to_base64("49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d") == "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"

  print_result(result, 1)
end

def challenge_2
  print_starting(2)

  # these are hex strings, so first unhex the strings and then xor them
  xord = xor_bytes(unhex("1c0111001f010100061a024b53535009181c"), unhex("686974207468652062756c6c277320657965"))

  # then pack them up again to normal char format and put it back into hex
  result = xord.pack("c*").unpack("H*").first == "746865206b696420646f6e277420706c6179"

  print_result(result, 2)
end

def challenge_3
  print_starting(3)

  ciphertext = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"
  ctext = unhex(ciphertext)
  expected = freq("alice_in_wonderland.txt")
  best = 1/0.0
  best_ptext = nil
  (0..255).each do |guess|
    ptext = xor(ctext, guess)
    current_score = score(ptext, expected)
    if current_score < best
      best = current_score
      best_ptext = ptext
    end
  end

  result = best_ptext.pack("c*") == "Cooking MC's like a pound of bacon"

  print_result(result, 3)
end

def challenge_4
  print_starting(4)

  expected = freq("alice_in_wonderland.txt")
  best = 1/0.0
  best_ptext = nil

  File.foreach("4.txt").each do |line|
    (0..255).each do |guess|
      ptext = xor(unhex(line), guess)
      current_score = score(ptext, expected)
      if current_score < best
        best = current_score
        best_ptext = ptext
      end
    end
  end

  result = best_ptext.pack("c*") == "Now that the party is jumping\n"

  print_result(result, 4)
end

def challenge_5
  print_starting(5)

  text = "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal"

  result = repeating_key_xor(text, "ICE").pack("c*").unpack("H*")

  result = result.first == "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f"

  print_result(result, 5)
end

def challenge_6
  print_starting(6)

  expected = freq("alice_in_wonderland.txt")

  file_content = Base64.decode64(File.read("6.txt")).bytes

  keysizes = [*2..40]

  candidates = keysizes.map do |keysize|
    normlised_distance = (0..5).reduce(0) do |mem, n|

      first_keysize = file_content[keysize * n * 2 .. keysize * (n * 2 + 1) - 1]
      second_keysize = file_content[keysize * (n * 2 + 1) .. keysize * (n * 2 + 2) - 1]

      raise "wtf" unless first_keysize.length == keysize
      raise "wtf" unless second_keysize.length == keysize

      mem += hamming_distance(first_keysize, second_keysize)/keysize.to_f
      mem
    end

    [normlised_distance, keysize]
  end

  candidates.sort!

  candidate_texts = candidates.map do |distance, keysize|
    # puts keysize
    # break if keysize != 29
    text_blocks = file_content.each_slice(keysize).map { |x| x }

    transposed = keysize.times.map do |key_idx|
      text_blocks.size.times.map do |block_idx|

        text_blocks[block_idx][key_idx]
      end.compact # need to remove any nils
    end

    solved = transposed.map do |block|
      best = 1/0.0
      key = nil

      (0..255).map {|char|
        ptext = xor(block, char)
        current_score = score(ptext, expected)
        if current_score < best
          best = current_score
          key = char
        end
      }

      key
    end

    repeating_key_xor_bytes(file_content, solved).pack("c*")
  end

  best = 1/0.0
  best_cand = nil

  candidate_texts.each do |cand|
    current_score = score(cand.bytes, expected)

    if current_score < best
      best = current_score
      best_cand = cand
    end

  end

  res = best_cand = "I'm back and I'm ringin' the bell \nA rockin' on the mike while the fly girls yell \nIn ecstasy in the back of me \nWell that's my DJ Deshay cuttin' all them Z's \nHittin' hard and the girlies goin' crazy \nVanilla's on the mike, man I'm not lazy. \n\nI'm lettin' my drug kick in \nIt controls my mouth and I begin \nTo just let it flow, let my concepts go \nMy posse's to the side yellin', Go Vanilla Go! \n\nSmooth 'cause that's the way I will be \nAnd if you don't give a damn, then \nWhy you starin' at me \nSo get off 'cause I control the stage \nThere's no dissin' allowed \nI'm in my own phase \nThe girlies sa y they love me and that is ok \nAnd I can dance better than any kid n' play \n\nStage 2 -- Yea the one ya' wanna listen to \nIt's off my head so let the beat play through \nSo I can funk it up and make it sound good \n1-2-3 Yo -- Knock on some wood \nFor good luck, I like my rhymes atrocious \nSupercalafragilisticexpialidocious \nI'm an effect and that you can bet \nI can take a fly girl and make her wet. \n\nI'm like Samson -- Samson to Delilah \nThere's no denyin', You can try to hang \nBut you'll keep tryin' to get my style \nOver and over, practice makes perfect \nBut not if you're a loafer. \n\nYou'll get nowhere, no place, no time, no girls \nSoon -- Oh my God, homebody, you probably eat \nSpaghetti with a spoon! Come on and say it! \n\nVIP. Vanilla Ice yep, yep, I'm comin' hard like a rhino \nIntoxicating so you stagger like a wino \nSo punks stop trying and girl stop cryin' \nVanilla Ice is sellin' and you people are buyin' \n'Cause why the freaks are jockin' like Crazy Glue \nMovin' and groovin' trying to sing along \nAll through the ghetto groovin' this here song \nNow you're amazed by the VIP posse. \n\nSteppin' so hard like a German Nazi \nStartled by the bases hittin' ground \nThere's no trippin' on mine, I'm just gettin' down \nSparkamatic, I'm hangin' tight like a fanatic \nYou trapped me once and I thought that \nYou might have it \nSo step down and lend me your ear \n'89 in my time! You, '90 is my year. \n\nYou're weakenin' fast, YO! and I can tell it \nYour body's gettin' hot, so, so I can smell it \nSo don't be mad and don't be sad \n'Cause the lyrics belong to ICE, You can call me Dad \nYou're pitchin' a fit, so step back and endure \nLet the witch doctor, Ice, do the dance to cure \nSo come up close and don't be square \nYou wanna battle me -- Anytime, anywhere \n\nYou thought that I was weak, Boy, you're dead wrong \nSo come on, everybody and sing this song \n\nSay -- Play that funky music Say, go white boy, go white boy go \nplay that funky music Go white boy, go white boy, go \nLay down and boogie and play that funky music till you die. \n\nPlay that funky music Come on, Come on, let me hear \nPlay that funky music white boy you say it, say it \nPlay that funky music A little louder now \nPlay that funky music, white boy Come on, Come on, Come on \nPlay that funky music \n"

  print_result(res, 6)
end

def decrypt(block, key, mode)
  cipher = OpenSSL::Cipher.new(mode)
  cipher.decrypt
  cipher.key = key
  cipher.update(Base64.decode64(block)) + cipher.final
end

def challenge_7
  data = File.read("7.txt")
  key = "YELLOW SUBMARINE"
  mode = 'AES-128-ECB'

  result = decrypt(data, key, mode) == "I'm back and I'm ringin' the bell \nA rockin' on the mike while the fly girls yell \nIn ecstasy in the back of me \nWell that's my DJ Deshay cuttin' all them Z's \nHittin' hard and the girlies goin' crazy \nVanilla's on the mike, man I'm not lazy. \n\nI'm lettin' my drug kick in \nIt controls my mouth and I begin \nTo just let it flow, let my concepts go \nMy posse's to the side yellin', Go Vanilla Go! \n\nSmooth 'cause that's the way I will be \nAnd if you don't give a damn, then \nWhy you starin' at me \nSo get off 'cause I control the stage \nThere's no dissin' allowed \nI'm in my own phase \nThe girlies sa y they love me and that is ok \nAnd I can dance better than any kid n' play \n\nStage 2 -- Yea the one ya' wanna listen to \nIt's off my head so let the beat play through \nSo I can funk it up and make it sound good \n1-2-3 Yo -- Knock on some wood \nFor good luck, I like my rhymes atrocious \nSupercalafragilisticexpialidocious \nI'm an effect and that you can bet \nI can take a fly girl and make her wet. \n\nI'm like Samson -- Samson to Delilah \nThere's no denyin', You can try to hang \nBut you'll keep tryin' to get my style \nOver and over, practice makes perfect \nBut not if you're a loafer. \n\nYou'll get nowhere, no place, no time, no girls \nSoon -- Oh my God, homebody, you probably eat \nSpaghetti with a spoon! Come on and say it! \n\nVIP. Vanilla Ice yep, yep, I'm comin' hard like a rhino \nIntoxicating so you stagger like a wino \nSo punks stop trying and girl stop cryin' \nVanilla Ice is sellin' and you people are buyin' \n'Cause why the freaks are jockin' like Crazy Glue \nMovin' and groovin' trying to sing along \nAll through the ghetto groovin' this here song \nNow you're amazed by the VIP posse. \n\nSteppin' so hard like a German Nazi \nStartled by the bases hittin' ground \nThere's no trippin' on mine, I'm just gettin' down \nSparkamatic, I'm hangin' tight like a fanatic \nYou trapped me once and I thought that \nYou might have it \nSo step down and lend me your ear \n'89 in my time! You, '90 is my year. \n\nYou're weakenin' fast, YO! and I can tell it \nYour body's gettin' hot, so, so I can smell it \nSo don't be mad and don't be sad \n'Cause the lyrics belong to ICE, You can call me Dad \nYou're pitchin' a fit, so step back and endure \nLet the witch doctor, Ice, do the dance to cure \nSo come up close and don't be square \nYou wanna battle me -- Anytime, anywhere \n\nYou thought that I was weak, Boy, you're dead wrong \nSo come on, everybody and sing this song \n\nSay -- Play that funky music Say, go white boy, go white boy go \nplay that funky music Go white boy, go white boy, go \nLay down and boogie and play that funky music till you die. \n\nPlay that funky music Come on, Come on, let me hear \nPlay that funky music white boy you say it, say it \nPlay that funky music A little louder now \nPlay that funky music, white boy Come on, Come on, Come on \nPlay that funky music \n"

  print_result(result, 7)
end

# challenge_1
# challenge_2
# challenge_3
# challenge_4
# challenge_5
# challenge_6
challenge_7