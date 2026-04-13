package com.summersec.attack.deser.payloads;

public interface ObjectPayload<T> { T getObject(Object paramObject) throws Exception;

    public static class Utils {
        private static String capitalize(String s) {
            if (s == null || s.isEmpty()) return s;
            return s.substring(0, 1).toUpperCase() + s.substring(1);
        }

        public static Class<? extends ObjectPayload> getPayloadClass(String className) {
            Class<? extends ObjectPayload> clazz = null;
            try {
                clazz = (Class)Class.forName("com.summersec.attack.deser.payloads." + capitalize(className));
            } catch (Exception exception) {}

            return clazz;
        }
    }
}

