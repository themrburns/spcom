spcom={...}if not fs.exists("ecc.lua")then error("spcom: ecc.lua not found in current directory, perhaps it isn't installed?",2)end;local a=require("ecc")local function b()local c=math.random;local d='xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'return string.gsub(d,'[xy]',function(e)return string.format('%x',e=='x'and c(0,0xf)or c(8,0xb))end)end;function spcom.init(f,g)assert(type(g)=="string"or g==nil,"init() param 2 is not a string")assert(f==true or f==false or f==nil,"init() param 1 is not a boolean value")f=f or false;if fs.exists("secret.key")or fs.exists("public.key")and f then error("Public and secret keyfiles already exist")end;g=g or a.random.random()local h,i=a.keypair(g)if f then local j=fs.open("public.key","w")j.write(tostring(h))j.close()j=fs.open("secret.key","w")j.write(tostring(i))j.close()end;if not fs.exists("spcom-garbage.txt")then local garbage={}local k=fs.open("spcom-garbage.txt","w")k.write(textutils.serialise(garbage))k.close()end;h=tostring(h)i=tostring(i)return{public=i,secret=h}end;function spcom.exchange(l,m)assert(type(m)=="string","exhange() public key is not a string")assert(type(l)=="string","exchange() secret key is not a string")return tostring(a.exchange(l,m))end;function spcom.createPacket(n,o,h)assert(type(n)=="string","createPacket() param 1 is not a string")assert(type(o)=="string","createPacket() param 2 is not a string")assert(type(h)=="string","createPacket() param 3 is not a string")local p=tostring(a.encrypt(n,o))local q=b()local r=os.time()local subpacket={msg=p,uuid=q,time=r}local s=tostring(a.sign(h,subpacket))return textutils.serialise({subpacket=subpacket,sig=s})end;function spcom.verifyPacket(t,o,i)assert(type(t)=="string","verifyPacket() param 1 is not serialised")assert(type(o)=="string","verifyPacket() param 2 is not a string")assert(type(i)=="string","verifyPacket() param 3 is not a string")if not fs.exists("spcom-garbage.txt")then error("UUID Garbage file not found")end;local u=fs.open("spcom-garbage.txt","r")garbage=textutils.unserialise(u.readAll())u.close()t=textutils.unserialise(t)subpacket=t.subpacket;sig=t.sig;local v=a.verify(i,subpacket,sig)if v then if os.time()-subpacket.time<=0.02 then if#garbage>0 then for w,x in ipairs(garbage)do if x==subpacket.uuid then return false end end end;table.insert(garbage,subpacket.uuid)local y=fs.open("spcom-garbage.txt","w")y.write(textutils.serialise(garbage),"w")y.close()return tostring(a.decrypt(subpacket.msg,o))end end;return false end;return spcom