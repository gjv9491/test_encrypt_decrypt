%dw 2.0
fun removePair(e: String, predicate) =
  e match {
    case is Array  -> e map removePair($, predicate)
    case is Object -> e mapObject (v, k) ->
                        if (predicate(k))
                          {}
                        else
                          {(k): removePair(v, predicate)}
    else           -> predicate - e
  }
/*
 * Pass in key and payload for removal of key from the payload
 *
 *  */