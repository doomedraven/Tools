# https://www.compose.com/articles/finding-duplicate-documents-in-mongodb/

* get duplicated values
```
use yeti
db.observable.aggregate([  
    {$group: { _id: {value: "$value"}, count: {$sum: 1}}},
    {$match: {count: {"$gt": 1}}},
    {$sort: {count: -1}}],
    {allowDiskUse:true, cursor:{}}
);
```

* remove duplicated
```
var duplicates = [];
db.observable.aggregate([  
    {$group: { _id: {value: "$value"}, count: {$sum: 1}, dups: { "$addToSet": "$_id" },}},
    {$match: {count: {"$gt": 1}}},
    {$sort: {count: -1}}],
    {allowDiskUse:true, cursor:{}}
).forEach(function(doc) {
    doc.dups.shift();      // First element skipped for deleting
    doc.dups.forEach( function(dupId){ 
        duplicates.push(dupId);   // Getting all duplicate ids
        }
    )    
});

db.observable.remove({_id:{$in:duplicates}})
```
