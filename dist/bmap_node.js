(function(){function r(e,n,t){function o(i,f){if(!n[i]){if(!e[i]){var c="function"==typeof require&&require;if(!f&&c)return c(i,!0);if(u)return u(i,!0);var a=new Error("Cannot find module '"+i+"'");throw a.code="MODULE_NOT_FOUND",a}var p=n[i]={exports:{}};e[i][0].call(p.exports,function(r){var n=e[i][1][r];return o(n||r)},p,p.exports,r,e,n,t)}return n[i].exports}for(var u="function"==typeof require&&require,i=0;i<t.length;i++)o(t[i]);return o}return r})()({1:[function(require,module,exports){
const bmap = {}

Map.prototype.getKey = function (searchValue) {
  for (let [key, value] of this.entries()) {
    if (value === searchValue)
      return key
  }
  return null
}

// Takes a bitdb formatted op_return transaction
bmap.TransformTx = (tx) => {
  if (!tx || !tx.hasOwnProperty('in') || !tx.hasOwnProperty('out')) {
    throw new Error('Cant process tx', tx)
  }

  let protocolMap = new Map()
  protocolMap.set('B','19HxigV4QyBv3tHpQVcUEQyq1pzZVdoAut')
  protocolMap.set('MAP','1PuQa7K62MiKCtssSLKy1kh56WWU7MtUR5')
  protocolMap.set('METANET', 'meta')
  protocolMap.set('AIP','15PciHG22SNLQJXMoSUaWVi7WSqc7hCfva')
  
  let encodingMap = new Map()
  encodingMap.set('utf8', 'string')
  encodingMap.set('text', 'string') // invalid but people use it :(
  encodingMap.set('gzip', 'binary') // invalid but people use it :(

  let querySchema = {
    'B': [
      { 'content': ['string', 'binary'] },
      { 'content-type': 'string' },
      { 'encoding': 'string' }, // we use this field to determine content character encoding. If encoding is not a valid character encoding (gzip), we assume it is binary
      { 'filename': 'string' }
    ],
    'MAP': [
      { 'cmd': 'string' },
      [
        { 'key': 'string' },
        { 'val': 'string' }
      ]
    ],
    'METANET': [
      { 'address': 'string'},
      { 'parent': 'string' },
      { 'name': 'string' },
      [ 
        {'kwd': 'string'}
      ]
    ],
    'AIP': [
      { 'algorithm': 'string' },
      { 'address': 'string' },
      { 'signature': 'binary' },
      [
        {'index': 'binary'}
      ]
    ],
    'default': [
      [{'pushdata': 'string'}]
    ]
  }

  // This will become our nicely formatted response object
  let dataObj = {}

  // offsets record the position of each protocol
  let offsets = new Map()

  // We always know what the first protocol is, it's always in s1
  let prefix = tx.out.filter(tx => { return tx && tx.b0.op === 106 })[0].s1

  // If s1 does not contain a protocol prefix, there's nothing to do
  if (!protocolMap.getKey(prefix)) {
    throw new Error('Unrecognized transaction', tx)
  }

  let protocolName = protocolMap.getKey(prefix)

  // Loop over the tx keys (in, out, tx, blk ...)
  for (let [key, val] of Object.entries(tx)) {
    
    // Check for op_return
    if (key === 'out' && tx.out.some((output) => { return output && output.b0 && output.b0.op === 106 })) {

      // There can be only one
      let opReturnOutput = val[0]

      // FIRST, we separate the string, key, and binary values
      let valueMaps = {
        'binary': new Map(),
        'string': new Map(),
        'hex': new Map()
      }

      let otherVals = {}
      let indexCount = 0
      let roundIndex = 0

      for (let pushdataKey in opReturnOutput) {
        // Get the TXO index number by itself (strip letters)
        let num = parseInt(pushdataKey.replace(/[A-Za-z]/g,''))
        if (num >= 0) {
          if (pushdataKey.startsWith('s') || pushdataKey.startsWith('ls')) {
            valueMaps.string.set(num, opReturnOutput[pushdataKey])
          } else if(pushdataKey.startsWith('b') || pushdataKey.startsWith('lb')) {
            valueMaps.binary.set(num, opReturnOutput[pushdataKey])
          } else if(pushdataKey.startsWith('h') || pushdataKey.startsWith('lh')) {
            valueMaps.hex.set(num, opReturnOutput[pushdataKey])
          }
          if (num > indexCount) {
            indexCount = num
          }
        } else {
          otherVals[pushdataKey] = opReturnOutput[pushdataKey]
        }
      }

      // Loop for pushdata count and find appropriate value
      let relativeIndex = 0
      for (let x = 0; x < indexCount; x++) {
        let stringVal = valueMaps.string.get(x + 1)
        // console.log('x', x, 'relative', relativeIndex, 'val', currentVal)
        if (relativeIndex === 0) {
          if (!protocolMap.getKey(stringVal)) {
            // Unknown protocol, just use the address as the key
            protocolName = stringVal
            querySchema[protocolName] = querySchema.default
          } else {
            protocolName = protocolMap.getKey(stringVal)
          }
          
          dataObj[protocolName] = []
          offsets.set(protocolName, x+1)
        }

        // Detect UNIX pipeline
        if (stringVal === '|') {
          // console.log('========================= End', protocolName)
          relativeIndex = 0
          continue
        }

        let encoding
        if (relativeIndex !== 0) {
          // get the schema object, or array of objects in case of repeating fields
          let schemaField = querySchema[protocolName][relativeIndex-1]
          if (!schemaField) { throw new Error('Failed to find schema field for ', protocolName) }

          let obj = {}

          if (schemaField instanceof Array) {
            // loop through the schema as we add values
            roundIndex = roundIndex % schemaField.length
            let thekey = Object.keys(schemaField[roundIndex++])[0]
            roundIndex = roundIndex % schemaField.length
            encoding = Object.values(schemaField[roundIndex++])[0]
            
            obj[thekey] = valueMaps[encoding].get(x + 1)

            dataObj[protocolName].push(obj)
            continue
          } else {
            // get the key, value pair from this query schema
          
            let schemaKey = Object.keys(schemaField)[0]
            let schemaEncoding = Object.values(schemaField)[0]

            // B has many encoding possibilities for content, look in index 2 relative to the protocol schema
            if (schemaEncoding instanceof Array) {                
              // if encoding field if not included in content array assume its binary
              let encodingLocation = 's' + (offsets.get(protocolName) + 2 + relativeIndex)
              let cleanEncoding = (opReturnOutput[encodingLocation] || '').toLowerCase().replace(/[-]/g, '')
              encoding = encodingMap.has(cleanEncoding) ? encodingMap.get(cleanEncoding) : 'binary'
            } else {
              encoding = schemaEncoding
            }
            
            // attach correct value to the output object
            let dataVal = valueMaps[encoding].get(x + 1)
            obj[schemaKey] = dataVal
            dataObj[protocolName].push(obj)
            relativeIndex++
          }
        } else {
          relativeIndex++
        }
      }

      // TRANSFORM MAP from {key: "keyname", val: "myval"} to {keyname: 'myval'}
      let keyTemp
      let newMap = {}
      for (const [key, val] of Object.entries(dataObj)) {
        if (key === 'MAP') {
          let i = 0
          for (let item of val) {
            let k = Object.keys(item)[0]
            let v = Object.values(item)[0]
            if (k === 'cmd') { newMap.cmd = v; continue }
            if (i % 2 === 0) {
              // MAP key
              keyTemp = v
            } else {
              // MAP value
              newMap[keyTemp] = v
            }
            i++
          }
          // ToDo - detect key with no val and remove it? or set it to ''?
          dataObj[key] = newMap
        } else {
          if (key === '_id' || key === 'tx' || key === 'in' || key === 'out' || key === 'blk') {
            continue            
          }
          // Reduce non MAP root node (unknown protocol)
          dataObj[key] = val.reduce(function(map, obj) {
            map[Object.keys(obj)[0]] = Object.values(obj)[0]
            return map
          }, {})
        }
      }

      dataObj.out = tx.out.filter(o => { return o && o.hasOwnProperty('e') &&  !(o && o.b0 && o.b0.op === 106) })

    } else {
      dataObj[key] = val
    }
  }
  return dataObj
}

exports.TransformTx = function(tx) {
  return bmap.TransformTx(tx)
}
},{}]},{},[1]);
