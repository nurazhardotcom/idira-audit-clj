(ns idira-audit.main
  "CLI entrypoint.
   Usage:
     bb -m idira-audit.main audit --mock [--format edn|json]
     bb -m idira-audit.main audit --base-url URL (--api-token T | --token-url U --client-id I --client-secret S)
     bb -m idira-audit.main audit --idsvc [--idsvc-url http://127.0.0.1:8081]
     bb -m idira-audit.main mock-server [--port 8899]
     bb -m idira-audit.main check-native"
  (:require [cheshire.core :as json]
            [clojure.string :as str]
            [idira-audit.auth :as auth]
            [idira-audit.idsvc :as idsvc]
            [idira-audit.mock :as mock]
            [idira-audit.rules :as rules]
            [idira-audit.scim :as scim]))

(defn- now-epoch [] (quot (System/currentTimeMillis) 1000))

(defn- parse-args [argv]
  (loop [xs (seq argv) opts {}]
    (if (empty? xs)
      opts
      (let [k (first xs)
            more (rest xs)
            v (first more)]
        (cond
          (= k "audit") (recur more (assoc opts :cmd :audit))
          (= k "mock-server") (recur more (assoc opts :cmd :mock-server))
          (= k "check-native") (recur more (assoc opts :cmd :check-native))
          (str/starts-with? k "--")
          (if (and (seq more) (some? v) (not (str/starts-with? v "--")))
            (recur (rest more) (assoc opts (keyword (subs k 2)) v))
            (recur more (assoc opts (keyword (subs k 2)) true)))
          :else (recur more opts))))))

(defn- emit [fmt report]
  (case fmt
    "json" (println (json/generate-string report {:pretty true}))
    (prn report)))

(defn- report [estate now]
  (let [findings (rules/audit-users estate now)]
    {:scanned-at now
     :summary (rules/summarize findings)
     :findings findings}))

(defn- cmd-audit [{:keys [mock base-url api-token token-url client-id
                          client-secret scope format idsvc idsvc-url]}]
  (let [fmt (or format "edn")]
    (cond
      mock
      (let [started (mock/start!)]
        (try
          (let [estate (scim/fetch-estate (:base-url started) "mock-token-123")]
            ;; fixed clock => byte-identical output every run
            (emit fmt (assoc (report estate mock/now-fixture) :source :mock)))
          (finally (mock/stop! started))))

      idsvc
      (let [url (or idsvc-url "http://127.0.0.1:8081")
            inv (idsvc/fetch-inventory url)
            estate (idsvc/->estate inv)]
        (emit fmt (assoc (report estate (now-epoch))
                         :source :idsvc :idsvc-url url)))

      base-url
      (let [token (or api-token
                      (auth/client-credentials-token
                       {:token-url token-url :client-id client-id
                        :client-secret client-secret :scope scope}))
            estate (scim/fetch-estate base-url token)]
        (emit fmt (assoc (report estate (now-epoch)) :source base-url)))

      :else
      (do (binding [*out* *err*]
            (println "audit needs one of: --mock, --idsvc, or --base-url"))
          (System/exit 2)))))

(defn- cmd-mock-server [{:keys [port]}]
  (let [started (mock/start! :port (if port (parse-long port) 8899))]
    (println "mock Idira API on" (:base-url started) "(Ctrl-C to stop)")
    @(promise)))

(defn- cmd-check-native []
  (let [has-ni (try (do (.. Runtime getRuntime
                            (exec (into-array String ["native-image" "--version"]))
                            waitFor)
                        true)
                      (catch Exception _ false))]
    (prn {:babashka (System/getProperty "babashka.version")
          :java (System/getProperty "java.version")
          :native-image (boolean has-ni)
          :note (if has-ni
                  "native-image present — see README 'Building the binary'"
                  "no native-image here; userspace install: curl -sL <graalvm-ce-url> | tar -xz -C ~/.local && ~/.local/graalvm/bin/gu install native-image")})))

(defn -main [& argv]
  (let [{:keys [cmd] :as opts} (parse-args (vec argv))]
    (case cmd
      :audit (cmd-audit opts)
      :mock-server (cmd-mock-server opts)
      :check-native (cmd-check-native)
      (do (println (:doc (meta #'idira-audit.main/-main)
                         "Usage: bb -m idira-audit.main <audit|mock-server|check-native> [opts]"))
          (System/exit 2)))))
