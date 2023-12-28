(ns com.tallyfor.flow.fire.flow-functions
  "Functions for working with fmnoise/flow: cljs-only version to allow tap> to work"
  (:require [cljs.pprint :refer [pprint]]
            [clojure.spec.alpha :as s]
            [fmnoise.flow :refer [Flow fail? then]]))

(extend-protocol Flow
  string
  (?ok [this f] (f this))
  (?err [this f] this)
  (?throw [this] this)

  boolean
  (?ok [this f] (f this))
  (?err [this f] this)
  (?throw [this] this)

  number
  (?ok [this f] (f this))
  (?err [this f] this)
  (?throw [this] this))


(def show
  #(-> % clj->js js/console.log))

(defn pprint-to-string
  [data]
  (with-out-str (pprint data)))

(defn show-result
  "Displays the name and value, and returns the value.
  When used in a flow sequence:
  `(thru #(show-result name %))` to show result;
  use `then` or `else` to show result only when not an error or an error respectively."
  ([name result]
   (show-result name identity result))
  ([name f result]
   (show "")
   (show name)
   (show (pprint-to-string (f result)))
   result))

(defn flow-reduce
  ([f coll]
   (condp = (count coll)
     0 (f)
     1 (first coll)
     (flow-reduce f (f (first coll) (second coll)) (drop 2 coll))))
  ([f val coll]
   (loop [acc val
          coll coll]
     (let [item (first coll)]
       (if (or
             ;; it's an exception:
             (fail? acc)
             ;; it has an :error field, presumably from an exception returned from another function:
             (some? (:error acc))
             ;; we're done:
             (nil? item))
         acc
         (recur (f acc item)
                (rest coll)))))))

(def problems-key :cljs.spec.alpha/problems)

(defn spec-failure->ex-info
  "Convert a clojure.spec failure into an ex-info"
  [spec value value-name failed-function-name]
  #_(tap> {:spec-failure->ex-info/value value})
  (let [explanation (s/explain-data spec value)
        problems (get explanation problems-key)]
    (ex-info (str "Spec failure: invalid " value-name)
             {:error {:type            :spec-failure
                      :value           value
                      :value-name      value-name
                      :problems        (vec problems)
                      :failed-function failed-function-name}})))

(defn flow-conform
  "If `value` conforms to `spec`, return it; otherwise return an ex-info representing the spec failure"
  [spec value value-name function-name]
  #_(tap> {:flow-conform/value value})
  (->> (try
         (s/conform spec value)
         (catch :default e
           #_(tap> {:flow-conform.catch/value value})
           (ex-info (str "Spec failure: invalid " value-name)
                    {:error {:message         (.-message e)
                             :value           value
                             :value-name      value-name
                             :exception       e
                             :failed-function function-name}})))
       (then (fn [validated-value]
               #_(tap> {:flow-conform/validated-value validated-value})
               (if (s/invalid? validated-value)
                 (spec-failure->ex-info spec value value-name function-name)
                 validated-value)))))

(defn combine-ex-infos
  [& ex-infos]
  (if (= 1 (count ex-infos))
    (first ex-infos)
    (let [message (apply str (interpose " and " (map ex-message ex-infos)))
          data {:error {:type   :multiple
                        :errors (mapv (fn [ex-info] (:error (ex-data ex-info))) ex-infos)}}]
      (ex-info message data))))
