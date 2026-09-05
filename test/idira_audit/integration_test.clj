(ns idira-audit.integration-test
  (:require [clojure.test :refer [deftest is testing use-fixtures]]
            [idira-audit.auth :as auth]
            [idira-audit.mock :as mock]
            [idira-audit.rules :as rules]
            [idira-audit.scim :as scim]))

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
