(ns pam-audit.integration-test
  (:require [clojure.test :refer [deftest is testing use-fixtures]]
            [pam-audit.auth :as auth]
            [pam-audit.fixture :as fixture]
            [pam-audit.idsvc :as idsvc]
            [pam-audit.idsvc-core :as idsvc-core]
            [pam-audit.mock :as mock]
            [pam-audit.normalize :as normalize]
            [pam-audit.rules :as rules]
            [pam-audit.scim :as scim]))

(def ^:dynamic *base* nil)

(defn with-mock [f]
  (let [started (mock/start!)]
    (try (binding [*base* (:base-url started)]
           (f))
         (finally (mock/stop! started)))))

(use-fixtures :each with-mock)

(deftest test-client-credentials-flow-against-mock
  (is (= "mock-token-123"
         (auth/client-credentials-token
          {:token-url (str *base* "/oauth2/token")
           :client-id "lab" :client-secret "s3cret"}))))

(deftest test-estate-round-trips-through-http
  (let [estate (scim/fetch-estate *base* "mock-token-123")]
    (testing "wire normalization reproduces the fixture"
      (is (= mock/estate-fixture estate)))
    (testing "end-to-end audit still finds exactly 5"
      (let [findings (rules/audit-users estate mock/now-fixture)]
        (is (= 5 (count findings)))
        (is (= 2 (count (filter #(= :high (:severity %)) findings))))))))

(deftest test-native-public-compatibility-aliases
  (let [inventory {:humans [{:name "alice"}]
                   :non_human_identities [{:name "worker" :sponsor "alice"}]}]
    (testing "fixture aliases"
      (is (= fixture/now-fixture mock/now-fixture))
      (is (= fixture/estate-fixture mock/estate-fixture)))
    (testing "SCIM normalizer aliases"
      (is (= normalize/normalize-user scim/normalize-user))
      (is (= normalize/normalize-group scim/normalize-group))
      (is (= normalize/normalize-token scim/normalize-token))
      (is (= normalize/normalize-policy scim/normalize-policy)))
    (testing "idsvc translation alias"
      (is (= (idsvc-core/->estate inventory)
             (idsvc/->estate inventory))))))
