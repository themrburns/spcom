spcom = {...}
    if not fs.exists("ecc.lua") then
        error("spcom: ecc.lua not found in current directory, perhaps it isn't installed?", 2)
    end
    local ecc = require("ecc")

    local function uuid4()
        local random = math.random
        local template ='xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'
        return string.gsub(template, '[xy]', function (c)
            return string.format('%x', c == 'x' and random(0, 0xf) or random(8, 0xb))
        end)
    end

    function spcom.init(save, passphrase)
        assert(type(passphrase) == "string" or passphrase == nil, "init() param 2 is not a string")
        assert(save == true or save == false or save == nil, "init() param 1 is not a boolean value")
        save = save or false
        if fs.exists("secret.key") or fs.exists("public.key") and save then error("Public and secret keyfiles already exist") end
        passphrase = passphrase or ecc.random.random()
        local secretKey, publicKey = ecc.keypair(passphrase)

        if save then
            local h = fs.open("public.key", "w")
            h.write(tostring(secretKey))
            h.close()
            h = fs.open("secret.key", "w")
            h.write(tostring(publicKey))
            h.close()
        end

        if not fs.exists("spcom-garbage.txt") then
            local garbage = {}
            local gH = fs.open("spcom-garbage.txt", "w")
            gH.write(textutils.serialise(garbage))
            gH.close()
        end
        secretKey = tostring(secretKey)
        publicKey = tostring(publicKey)
        return {public=publicKey, secret=secretKey}
    end
    function spcom.exchange(secret, public)
        assert(type(public) == "string", "exhange() public key is not a string")
        assert(type(secret) == "string", "exchange() secret key is not a string")

        return tostring(ecc.exchange(secret, public))
    end
    function spcom.createPacket(content, sharedKey, secretKey)
        assert(type(content) == "string", "createPacket() param 1 is not a string")
        assert(type(sharedKey) == "string", "createPacket() param 2 is not a string")
        assert(type(secretKey) == "string", "createPacket() param 3 is not a string")

        local cipher = tostring(ecc.encrypt(content, sharedKey))
        local uuid = uuid4()
        local time = os.time()
        
        local subpacket = {msg=cipher, uuid=uuid, time=time}
        local signature = tostring(ecc.sign(secretKey, subpacket))

        return textutils.serialise({subpacket=subpacket, sig=signature})
    end
    function spcom.verifyPacket(packet, sharedKey, publicKey)
        assert(type(packet) == "string", "verifyPacket() param 1 is not serialised")
        assert(type(sharedKey) == "string", "verifyPacket() param 2 is not a string")
        assert(type(publicKey) == "string", "verifyPacket() param 3 is not a string")

        if not fs.exists("spcom-garbage.txt") then error("UUID Garbage file not found") end
        local gR = fs.open("spcom-garbage.txt", "r")
        garbage = textutils.unserialise(gR.readAll())
        gR.close()

        packet = textutils.unserialise(packet)
        subpacket = packet.subpacket
        sig = packet.sig
        
        local valid = ecc.verify(publicKey, subpacket, sig)
        if valid then
            
            if os.time() - subpacket.time <= 0.02 then
                if #garbage > 0 then
                    for _,v in ipairs(garbage) do
                        if v == subpacket.uuid then 
                            return false
                        end
                    end
                end
                table.insert(garbage, subpacket.uuid)
                local ngH = fs.open("spcom-garbage.txt", "w")
                ngH.write(textutils.serialise(garbage), "w")
                ngH.close()
                return tostring(ecc.decrypt(subpacket.msg, sharedKey))
            end
        end
        return false
    end
return spcom
