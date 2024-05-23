<?php 
$defaultdata=array( "showpassword"=>"no", "bgcolor"=>"#ffffff");

    function xor_encrypt($in , $key) {
    
        $text = $in;
        $outText = '';

        // Iterate through each character
        for($i=0;$i<strlen($text);$i++) 
        { 
            $outText .=$text[$i] ^ $key[$i % strlen($key)]; 
        } 
        return $outText; 
    } 

    $cookie = "MGw7JCQ5OC04PT8jOSpqdmkgJ25nbCorKCEkIzlscm5oKC4qLSgubjY=";
    $cipher_text = base64_decode($cookie);
    $org_data =  json_encode($defaultdata);

   echo(xor_encrypt($org_data,$cipher_text));
   
   $spoof_data = json_encode(array("showpassword" => "yes" , "bgcolor" => "#ffffff"));
   $key = "KNHL";
   
   $new_cookie = xor_encrypt($spoof_data, $key);
   echo("\n");
   echo(base64_encode($new_cookie));
        
?>