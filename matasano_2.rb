#!/usr/bin/ruby

def hex_to_base64(str)
  [[str].pack("H*")].pack("m0")
end

def print_result(bool, challenge)
  to_print = bool ? "Challenge #{challenge} passed" : "Challenge #{challenge} failed"
  puts to_print
end

def challenge_1
  result = hex_to_base64("49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d") == "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"

  print_result(result, 1)
end

def unhex(str)
  [str].pack("H*")
end

def xor_bytes(bytes, bytes_2)
  bytes.zip(bytes_2).map { |l,r| l^r }
end

def xor(str1, str2)
  xor_bytes(str1.bytes, str2.bytes)
end

def repeating_key_xor(string, repeating_key)
  xor_bytes(string.bytes, repeating_key.bytes.cycle)
end

def challenge_2
  # these are hex strings, so first unhex the strings and then xor them
  xord = xor(unhex("1c0111001f010100061a024b53535009181c"), unhex("686974207468652062756c6c277320657965"))

  # then pack them up again to normal char format and put it back into hex
  result = xord.pack("c*").unpack("H*").first == "746865206b696420646f6e277420706c6179"

  print_result(result, 2)
end

# checks if a byte is a printable ASCII character (between 32 126)
def printable_byte?(candidate)
  # char 10 is the newline char
  candidate.chars.all? {|char| char.ord.between?(32,126) || char.ord == 10}
end

# score against english language frequency distribution
def frequency_score(str)
  str = str.downcase
  freqs = {"e"=> 0.12702,
          "t" => 0.09056,
          "a" => 0.08167,
          "o" => 0.07507,
          "i" => 0.06966,
          "n" => 0.06749,
          "s" => 0.06327,
          "h" => 0.06094,
          "r" => 0.05987,
          "d" => 0.04253,
          "l" => 0.04025,
          "c" => 0.02782,
          "u" => 0.02758,
          "m" => 0.02406,
          "w" => 0.02360,
          "f" => 0.02228,
          "g" => 0.02015,
          "y" => 0.01974,
          "p" => 0.01929,
          "b" => 0.01492,
          "v" => 0.00978,
          "k" => 0.00772,
          "j" => 0.00153,
          "x" => 0.00150,
          "q" => 0.00095,
          "z" => 0.00074}
  scores = {}

  ('a'..'z').reduce(0) {|score, char| score + (freqs[char] - (str.count(char) / str.length.to_f)).abs}
end

def bytes_to_str(arr)
  arr.pack("c*")
end

def brute(ciphertext)
  (0..255).map {|char|
    xor(unhex(ciphertext), unhex(char.to_s * ciphertext.length)).pack("c*")
  }
end

def printable_candidates(arr)
  arr.select {|candidate| printable_byte?(candidate) }
end

def printable_ordered_candidates(arr)
  arr.select {|candidate| printable_byte?(candidate) }
    .sort {|c1,c2| frequency_score(c1) <=> frequency_score(c2)}
end

def challenge_3
  ciphertext = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"

  result = printable_ordered_candidates(brute(ciphertext)).first == "Cooking MC's like a pound of bacon"

  print_result(result, 3)
end

def challenge_4
  all_xord = File.foreach("4.txt").map do |line|
    brute(line.gsub("\n", ''))
  end.flatten

  result = printable_ordered_candidates(all_xord).first == "Now that the party is jumping\n"

  print_result(result, 4)
end

def challenge_5
  text = "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal"

  result = repeating_key_xor(text, "ICE").pack("c*").unpack("H*")

  result = result.first == "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f"

  print_result(result, 5)
end

def challenge_6

end

# challenge_1
# challenge_2
# challenge_3
# challenge_4
# challenge_5
# challenge_6