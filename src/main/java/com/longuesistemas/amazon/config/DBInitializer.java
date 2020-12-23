package com.longuesistemas.amazon.config;





import javax.annotation.PostConstruct;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import com.amazonaws.services.dynamodbv2.datamodeling.DynamoDBMapper;
import com.amazonaws.services.dynamodbv2.document.DynamoDB;
import com.amazonaws.services.dynamodbv2.document.Table;
import com.amazonaws.services.dynamodbv2.model.CreateTableRequest;
import com.amazonaws.services.dynamodbv2.model.ProvisionedThroughput;
import com.amazonaws.services.dynamodbv2.model.ResourceInUseException;
import com.longuesistemas.dto.Pessoa;


@Component
public class DBInitializer
{
    private DynamoDBMapper mapper;
    private DynamoDB       client;
    private Logger logger = LoggerFactory.getLogger(DBInitializer.class);

    @Autowired
    public DBInitializer(DynamoDBMapper mapper, DynamoDB client)
    {
        this.mapper = mapper;
        this.client = client;
    }

    @PostConstruct
    public void init() throws InterruptedException
    {
        createTableWithMapper();
    }

     private void createTableWithMapper() throws InterruptedException
    {
        CreateTableRequest request = mapper.generateCreateTableRequest(Pessoa.class);
        ProvisionedThroughput provisionedThroughput = new ProvisionedThroughput(1L, 1L);
        request.setProvisionedThroughput(provisionedThroughput);
//        request.getGlobalSecondaryIndexes().forEach(index->{
//                    index.setProvisionedThroughput(provisionedThroughput);
//                    index.setProjection(new Projection().withProjectionType(ProjectionType.ALL));
//                }
//        );

        try
        {
            Table table = client.createTable(request);
            table.waitForActive();
        }
        catch (ResourceInUseException e)
        {
        	logger.info("Table {} already exists", request.getTableName());
        }
    }
}
