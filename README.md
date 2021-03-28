# hook_ArtMethod_RegisterNative
1. 将libext.so 和libext64.so 放到 /data/app 目录下, chmod 777 , 并setenforce 0
2. frida -U -f 包名 -l hook_artmethod_register.js --no-pause


包含yang神的hook RegisterNatives 可以比较是否相同 参考 yang神的hook artmethod.js 来打印 ArtMethod* 得到函数的方法和签名 
hook ArtMethod::RegisterNative 可以得到更多的信息,动态注册无法逃离这个函数,防止某些app自实现动态注册,不走jni的registerNatives 
