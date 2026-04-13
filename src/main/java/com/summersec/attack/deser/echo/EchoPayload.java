package com.summersec.attack.deser.echo;

import javassist.ClassPool;
import javassist.CtClass;



public interface EchoPayload<T> {
    CtClass genPayload(ClassPool paramClassPool) throws Exception;

    public static class Utils
    {
        private static String capitalize(String s) {
            if (s == null || s.isEmpty()) return s;
            return s.substring(0, 1).toUpperCase() + s.substring(1);
        }

        public static Class<? extends EchoPayload> getPayloadClass(String className) throws ClassNotFoundException {
            Class<? extends EchoPayload> clazz = null;
            try {
                clazz = (Class)Class.forName("com.summersec.attack.deser.echo." + capitalize(className));
            } catch (ClassNotFoundException e1) {
                clazz = (Class)Class.forName("com.summersec.attack.deser.plugins." + capitalize(className));
            } catch (Exception e) {
                e.printStackTrace();
            }
            return clazz;
        }
    }
}



