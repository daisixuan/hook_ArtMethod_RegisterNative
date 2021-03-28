/*
1. 将libext.so 和libext64.so 放到 /data/app 目录下, chmod 777 , 并setenforce 0
2. frida -U -f 包名 -l hook_artmethod_register.js --no-pause
包含yang神的hook RegisterNatives 可以比较是否相同 参考 yang神的hook artmethod.js 来打印 ArtMethod* 得到函数的方法和签名 
hook ArtMethod::RegisterNative 可以得到更多的信息,动态注册无法逃离这个函数,防止某些app自实现动态注册,不走jni的registerNatives 
*/

function hook_ArtMethodRegister() {
    var symbols = Module.enumerateSymbolsSync("libart.so");

    var ArtMethodRegisterNative = null;
    var ArtMethod_PrettyMethod = null;
    for (var i = 0; i < symbols.length; i++) {
        var symbol = symbols[i];
        var address = symbol.address;
        var name = symbol.name;
        var indexArtMethod = name.indexOf("ArtMethod");
        //_ZN3art9ArtMethod14RegisterNativeEPKv android 10
        if (
            name.indexOf("ArtMethod") >= 0 &&
            name.indexOf("RegisterNative") >= 0 &&
            name.indexOf("Callback") < 0
        ) {
            console.log("ArtMethod::RegisterNative is at ", address, name);
            ArtMethodRegisterNative = address;
        }
        if (indexArtMethod >= 0 && name.indexOf("PrettyMethod") >= 0 && name.indexOf("Eb") >= 0) {
            console.log("ArtMethod::PrettyMethod is at ", address, name);
            ArtMethod_PrettyMethod = address;
        }
    }
    var module_libext = null;
    if (Process.arch === "arm64") {
        module_libext = Module.load("/data/app/libext64.so");
    } else if (Process.arch === "arm") {
        module_libext = Module.load("/data/app/libext.so");
    }
    if (module_libext != null) {
        var addr_PrettyMethod = module_libext.findExportByName("PrettyMethod");
        var PrettyMethod = new NativeFunction(addr_PrettyMethod, "void", ["pointer", "pointer", "pointer", "int"]);

        if (ArtMethodRegisterNative) {
            //var foo_ArtMethod_PrettyMethod = new NativeFunction(ArtMethod_PrettyMethod, "pointer", ["pointer", "int"]);
            Interceptor.attach(ArtMethodRegisterNative, {
                onEnter: function (args) {
                    try {
                        // console.log(this.context.x0);
                        // console.log(this.context.x1);
                        // console.log(this.context.x2);
                        // console.log(this.context.x3);
                        // console.log(args[0],args[1],args[2],args[3])
                        var result = Memory.alloc(0x100);
                        var fnPtr_ptr = args[1];
                        var find_module = Process.findModuleByAddress(fnPtr_ptr);
                        var offset = ptr(fnPtr_ptr).sub(find_module.base)
                        PrettyMethod(ArtMethod_PrettyMethod, args[0], result, 0x100);
                        console.log("[ArtMethod_RegisterNative] Method_sig:", result.readCString(), "module_name:", find_module.name, "offset:", offset);
                    } catch (error) {
                        console.log(error);
                    }

                }, onLeave: function (retval) {

                }
            });
        }
    }
}

function hook_RegisterNatives() {
    var symbols = Module.enumerateSymbolsSync("libart.so");
    var addrRegisterNatives = null;
    for (var i = 0; i < symbols.length; i++) {
        var symbol = symbols[i];

        //_ZN3art3JNI15RegisterNativesEP7_JNIEnvP7_jclassPK15JNINativeMethodi
        if (symbol.name.indexOf("art") >= 0 &&
            symbol.name.indexOf("JNI") >= 0 &&
            symbol.name.indexOf("RegisterNatives") >= 0 &&
            symbol.name.indexOf("CheckJNI") < 0) {
            addrRegisterNatives = symbol.address;
            console.log("RegisterNatives is at ", symbol.address, symbol.name);
        }
    }

    if (addrRegisterNatives != null) {
        Interceptor.attach(addrRegisterNatives, {
            onEnter: function (args) {
                //console.log("[RegisterNatives] method_count:", args[3]);
                var env = args[0];
                var java_class = args[1];
                var class_name = Java.vm.tryGetEnv().getClassName(java_class);
                //console.log(class_name);

                var methods_ptr = ptr(args[2]);

                var method_count = parseInt(args[3]);
                for (var i = 0; i < method_count; i++) {
                    var name_ptr = Memory.readPointer(methods_ptr.add(i * Process.pointerSize * 3));
                    var sig_ptr = Memory.readPointer(methods_ptr.add(i * Process.pointerSize * 3 + Process.pointerSize));
                    var fnPtr_ptr = Memory.readPointer(methods_ptr.add(i * Process.pointerSize * 3 + Process.pointerSize * 2));

                    var name = Memory.readCString(name_ptr);
                    var sig = Memory.readCString(sig_ptr);
                    var find_module = Process.findModuleByAddress(fnPtr_ptr);
                    console.log("[RegisterNatives] java_class:", class_name, "name:", name, "sig:", sig, "fnPtr:", fnPtr_ptr, "module_name:", find_module.name, "module_base:", find_module.base, "offset:", ptr(fnPtr_ptr).sub(find_module.base));

                }
            }
        });
    }
}

//setImmediate(hook_native);
setImmediate(hook_ArtMethodRegister)
setImmediate(hook_RegisterNatives);

