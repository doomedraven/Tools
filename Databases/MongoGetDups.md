* https://www.compose.com/articles/finding-duplicate-documents-in-mongodb/

```
use yeti
db.observable.aggregate([  
    {$group: { _id: {value: "$value"}, count: {$sum: 1}}},
    {$match: {count: {"$gt": 1}}},
    {$sort: {count: -1}}],
    {allowDiskUse:true, cursor:{}}
);
```
