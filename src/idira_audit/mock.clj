(ns idira-audit.mock
  "In-process stub of a CyberArk/Idira-style REST API, built only on
   JDK java.net.ServerSocket (java.base — no extra modules, no deps).
   Serves a deterministic estate with exactly 5 expected findings
   (see estate-fixture), so tests and demos assert exact counts."
  (:require [cheshire.core :as json]
            [clojure.java.io :as io]
            [clojure.string :as str])
  (:import [java.net ServerSocket]
           [java.nio.charset StandardCharsets]))

;; Fixed clock for determinism: 2026-09-05T00:00:00Z ≈ 1788460800
(def now-fixture 1788460800)
(def ^:private day 86400)
(defn- days-ago [n] (- now-fixture (* n day)))

;; ---------- deterministic estate (normalized shape) ----------

(def estate-fixture
  {:users
   [{:id "ciso" :kind :human :active true :owner-id nil
     :mfa-enrolled true :assurance :adaptive-mfa
     :vault-managed true :device-compliant true
     :last-login (days-ago 1)}
    {:id "admin-active" :kind :human :active true :owner-id "ciso"
     :mfa-enrolled true :assurance :mfa
     :vault-managed true :device-compliant true
     :last-login (days-ago 2)}
    {:id "svc-orphan" :kind :service :active true :owner-id nil
     :mfa-enrolled true :assurance :mfa
     :vault-managed true :device-compliant true
     :last-login (days-ago 2)}
    {:id "svc-dormant" :kind :service :active true :owner-id "ciso"
     :mfa-enrolled true :assurance :mfa
     :vault-managed true :device-compliant true
     :last-login (days-ago 120)}
    {:id "svc-unvaulted" :kind :service :active true :owner-id "ciso"
     :mfa-enrolled true :assurance :mfa
     :vault-managed false :device-compliant true
     :last-login (days-ago 3)}
    {:id "analyst-nomfa" :kind :human :active true :owner-id nil
     :mfa-enrolled false :assurance :none
     :vault-managed true :device-compliant false
     :last-login (days-ago 1)}]
   :groups
   [{:id "vault-admins" :privileged true
     :members ["admin-active" "svc-orphan" "svc-dormant" "svc-unvaulted"]}
    {:id "analysts" :privileged false
     :members ["analyst-nomfa" "ciso"]}]
   :tokens
   [{:id "tok-stale" :owner-id "svc-dormant"
     :created (days-ago 200) :revoked false}
    {:id "tok-fresh" :owner-id "admin-active"
     :created (days-ago 2) :revoked false}]
   :policies
   {:require-mfa true
    :min-assurance :mfa
    :require-adaptive-mfa true
    :require-device-posture true
    :max-inactive-days 90
    :privileged-token-ttl-days 180
    :require-vaulting true}})

;; ---------- wire shape (camelCase, SCIM-ish) ----------

(defn- user->wire [u]
  {:id (:id u) :userName (:id u) :kind (name (:kind u))
   :active (:active u) :ownerId (:owner-id u)
   :mfaEnrolled (:mfa-enrolled u) :assurance (name (:assurance u))
   :vaultManaged (:vault-managed u) :deviceCompliant (:device-compliant u)
   :lastLogin (:last-login u)})

(defn- token->wire [t]
  {:id (:id t) :ownerId (:owner-id t)
   :created (:created t) :revoked (:revoked t)})

(defn- policy->wire [p]
  {:requireMfa (:require-mfa p) :minAssurance (name (:min-assurance p))
   :requireAdaptiveMfa (:require-adaptive-mfa p)
   :requireDevicePosture (:require-device-posture p)
   :maxInactiveDays (:max-inactive-days p)
   :privilegedTokenTtlDays (:privileged-token-ttl-days p)
   :requireVaulting (:require-vaulting p)})

(defn- routes []
  {"/oauth2/token"
   {:status 200 :body {:access_token "mock-token-123"
                       :token_type "Bearer" :expires_in 3600}}
   "/scim/v2/Users"
   {:status 200 :body {:Resources (mapv user->wire (:users estate-fixture))
                       :totalResults (count (:users estate-fixture))}}
   "/scim/v2/Groups"
   {:status 200 :body {:Resources (mapv (fn [g] {:id (:id g)
                                                :privileged (:privileged g)
                                                :members (:members g)})
                                        (:groups estate-fixture))
                       :totalResults (count (:groups estate-fixture))}}
   "/api/v1/tokens"
   {:status 200 :body {:Resources (mapv token->wire (:tokens estate-fixture))
                       :totalResults (count (:tokens estate-fixture))}}
   "/api/v1/policies/mfa"
   {:status 200 :body {:policy (policy->wire (:policies estate-fixture))}}})

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
