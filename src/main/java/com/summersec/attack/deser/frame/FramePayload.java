package com.summersec.attack.deser.frame;

public interface FramePayload<T> {
    String sendpayload(Object var1, String var2, String var3) throws Exception;

    String sendpayload(Object var1) throws Exception;

    public static class Utils {
        private static String capitalize(String s) {
            if (s == null || s.isEmpty()) return s;
            return s.substring(0, 1).toUpperCase() + s.substring(1);
        }

        public static Class<? extends FramePayload> getPayloadClass(String className) {
            Class clazz = null;

            try {
                clazz = Class.forName("com.summersec.attack.deser.frame." + capitalize(className));
            } catch (Exception var3) {
            }

            return clazz;
        }
    }
}



