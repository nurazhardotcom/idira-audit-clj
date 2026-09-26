(ns pam-audit.mock
  "In-process stub of a SCIM-shaped PAM REST API, built only on
   JDK java.net.ServerSocket (java.base — no extra modules, no deps).
   Serves a deterministic estate with exactly 5 expected findings
   (see estate-fixture), so tests and demos assert exact counts."
  (:require [cheshire.core :as json]
            [clojure.java.io :as io]
            [clojure.string :as str]
            [pam-audit.fixture :as fixture]
            [pam-audit.wire :as wire])
  (:import [java.net ServerSocket]
           [java.nio.charset StandardCharsets]))

;; Compatibility vars retained for existing native callers.
(def now-fixture fixture/now-fixture)
(def estate-fixture fixture/estate-fixture)

(defn- routes []
  {"/oauth2/token"
   {:status 200 :body {:access_token "mock-token-123"
                       :token_type "Bearer" :expires_in 3600}}
   "/scim/v2/Users"
   {:status 200 :body {:Resources (mapv wire/user->wire (:users estate-fixture))
                       :totalResults (count (:users estate-fixture))}}
   "/scim/v2/Groups"
   {:status 200 :body {:Resources (mapv (fn [g] {:id (:id g)
                                                :privileged (:privileged g)
                                                :members (:members g)})
                                        (:groups estate-fixture))
                       :totalResults (count (:groups estate-fixture))}}
   "/api/v1/tokens"
   {:status 200 :body {:Resources (mapv wire/token->wire (:tokens estate-fixture))
                       :totalResults (count (:tokens estate-fixture))}}
   "/api/v1/policies/mfa"
   {:status 200 :body {:policy (wire/policy->wire (:policies estate-fixture))}}})

;; ---------- minimal HTTP/1.1 stub over ServerSocket ----------

(defn- read-request [in]
  (let [rdr (io/reader in :encoding "UTF-8")
        request-line (.readLine rdr)
        [_ path _] (when request-line (str/split request-line #" " 3))
        headers (loop [acc {}]
                  (let [line (.readLine rdr)]
                    (if (or (nil? line) (str/blank? line))
                      acc
                      (let [[k v] (str/split line #":" 2)]
                        (recur (assoc acc (str/lower-case (str/trim k))
                                      (str/trim (or v ""))))))))
        n (parse-long (get headers "content-length" "0"))
        _ (when (pos? n)
            (let [buf (char-array n)]
              (loop [off 0]
                (when (< off n)
                  (let [r (.read rdr buf off (- n off))]
                    (when (pos? r) (recur (+ off r))))))))]
    {:method (first (str/split (or request-line "") #" "))
     :path path}))

(defn- write-response [out status data]
  (let [body (.getBytes (json/generate-string data) StandardCharsets/UTF_8)
        head (str "HTTP/1.1 " status " OK\r\n"
                  "Content-Type: application/json\r\n"
                  "Content-Length: " (alength body) "\r\n"
                  "Connection: close\r\n\r\n")]
    (.write out (.getBytes head StandardCharsets/US_ASCII))
    (.write out body)
    (.flush out)))

(defn- serve-one [socket]
  (with-open [sock socket]
    (try
      (let [{:keys [path]} (read-request (.getInputStream sock))
            {:keys [status body]} (get (routes) path
                                       {:status 404 :body {:error "not found"}})]
        (write-response (.getOutputStream sock) status body))
      (catch Exception _ nil))))

(defn start!
  "Start the stub API. Returns {:port :base-url :stop!}.
   Pass :port 0 (default) for an ephemeral port."
  [& {:keys [port] :or {port 0}}]
  (let [ss (ServerSocket. port)
        running (atom true)]
    (future
      (while @running
        (try (serve-one (.accept ss))
             (catch Exception _ nil))))
    {:port (.getLocalPort ss)
     :base-url (str "http://127.0.0.1:" (.getLocalPort ss))
     :stop! (fn [] (reset! running false) (.close ss))}))

(defn stop! [{:keys [stop!]}] (stop!))
