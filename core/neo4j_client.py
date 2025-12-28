"""
Neo4j Client for Cloud Policy Graph Database
Manages connections and operations with Neo4j graph database.
"""

import os
import logging
from typing import Dict, List, Any, Optional
from neo4j import GraphDatabase, Session
from neo4j.exceptions import ServiceUnavailable, AuthError


class Neo4jClient:
    """
    Neo4j database client for cloud policy graph operations.

    Manages:
    - Database connections
    - Graph schema creation
    - Node and relationship management
    - Cypher query execution
    - Transaction handling
    """

    def __init__(
        self,
        uri: str,
        username: str,
        password: str,
        database: str = "neo4j"
    ):
        """
        Initialize Neo4j client.

        Args:
            uri: Neo4j connection URI (e.g., bolt://localhost:7687)
            username: Database username
            password: Database password
            database: Database name (default: neo4j)
        """
        self.uri = uri
        self.username = username
        self.database = database
        self.logger = logging.getLogger(self.__class__.__name__)

        try:
            self.driver = GraphDatabase.driver(uri, auth=(username, password))
            # Test connection
            self.driver.verify_connectivity()
            self.logger.info(f"Successfully connected to Neo4j at {uri}")
        except ServiceUnavailable as e:
            self.logger.error(f"Failed to connect to Neo4j at {uri}: {str(e)}")
            raise
        except AuthError as e:
            self.logger.error(f"Authentication failed for Neo4j: {str(e)}")
            raise

    def close(self):
        """Close the database connection."""
        if self.driver:
            self.driver.close()
            self.logger.info("Neo4j connection closed")

    def __enter__(self):
        """Context manager entry."""
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit."""
        self.close()

    def execute_query(
        self,
        query: str,
        parameters: Optional[Dict[str, Any]] = None
    ) -> List[Dict[str, Any]]:
        """
        Execute a Cypher query and return results.

        Args:
            query: Cypher query string
            parameters: Query parameters

        Returns:
            List of result records as dictionaries
        """
        with self.driver.session(database=self.database) as session:
            result = session.run(query, parameters or {})
            return [record.data() for record in result]

    def execute_write(
        self,
        query: str,
        parameters: Optional[Dict[str, Any]] = None
    ) -> Any:
        """
        Execute a write transaction.

        Args:
            query: Cypher query string
            parameters: Query parameters

        Returns:
            Transaction result
        """
        with self.driver.session(database=self.database) as session:
            return session.execute_write(
                lambda tx: tx.run(query, parameters or {}).data()
            )

    def create_constraints(self):
        """
        Create database constraints and indexes for policy graph.

        Ensures:
        - Unique constraints on node identifiers
        - Indexes for common queries
        - Performance optimization
        """
        constraints = [
            # Principal constraints
            "CREATE CONSTRAINT principal_id IF NOT EXISTS FOR (p:Principal) REQUIRE p.id IS UNIQUE",

            # Resource constraints
            "CREATE CONSTRAINT resource_arn IF NOT EXISTS FOR (r:Resource) REQUIRE r.arn IS UNIQUE",

            # Policy constraints
            "CREATE CONSTRAINT policy_id IF NOT EXISTS FOR (p:Policy) REQUIRE p.id IS UNIQUE",

            # Action constraints
            "CREATE CONSTRAINT action_name IF NOT EXISTS FOR (a:Action) REQUIRE a.name IS UNIQUE",
        ]

        indexes = [
            # Indexes for common queries
            "CREATE INDEX principal_type IF NOT EXISTS FOR (p:Principal) ON (p.type)",
            "CREATE INDEX principal_name IF NOT EXISTS FOR (p:Principal) ON (p.name)",
            "CREATE INDEX resource_type IF NOT EXISTS FOR (r:Resource) ON (r.type)",
            "CREATE INDEX resource_name IF NOT EXISTS FOR (r:Resource) ON (r.name)",
            "CREATE INDEX policy_name IF NOT EXISTS FOR (p:Policy) ON (p.name)",
            "CREATE INDEX policy_vulnerable IF NOT EXISTS FOR (p:Policy) ON (p.vulnerable)",
        ]

        for constraint in constraints:
            try:
                self.execute_write(constraint)
                self.logger.debug(f"Created constraint: {constraint}")
            except Exception as e:
                # Constraint may already exist
                self.logger.debug(f"Constraint creation skipped: {str(e)}")

        for index in indexes:
            try:
                self.execute_write(index)
                self.logger.debug(f"Created index: {index}")
            except Exception as e:
                # Index may already exist
                self.logger.debug(f"Index creation skipped: {str(e)}")

    def clear_database(self):
        """
        Clear all nodes and relationships from the database.

        WARNING: This will delete all data!
        """
        query = "MATCH (n) DETACH DELETE n"
        self.execute_write(query)
        self.logger.warning("Database cleared - all nodes and relationships deleted")

    def create_principal(
        self,
        principal_id: str,
        principal_type: str,
        name: str,
        properties: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Create a Principal node (User, Role, Service Account, Group).

        Args:
            principal_id: Unique identifier
            principal_type: Type (user, role, service_account, group)
            name: Principal name
            properties: Additional properties

        Returns:
            Created node data
        """
        query = """
        MERGE (p:Principal {id: $id})
        SET p.type = $type,
            p.name = $name,
            p.created = datetime()
        SET p += $properties
        RETURN p
        """
        params = {
            "id": principal_id,
            "type": principal_type,
            "name": name,
            "properties": properties or {}
        }
        return self.execute_write(query, params)

    def create_resource(
        self,
        arn: str,
        resource_type: str,
        name: str,
        properties: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Create a Resource node (S3 bucket, EC2, Database, etc.).

        Args:
            arn: Amazon Resource Name or equivalent
            resource_type: Type of resource
            name: Resource name
            properties: Additional properties

        Returns:
            Created node data
        """
        query = """
        MERGE (r:Resource {arn: $arn})
        SET r.type = $type,
            r.name = $name,
            r.created = datetime()
        SET r += $properties
        RETURN r
        """
        params = {
            "arn": arn,
            "type": resource_type,
            "name": name,
            "properties": properties or {}
        }
        return self.execute_write(query, params)

    def create_action(
        self,
        action_name: str,
        category: str = "unknown",
        properties: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Create an Action node (permission/operation).

        Args:
            action_name: Action name (e.g., s3:GetObject)
            category: Action category (read, write, delete, admin)
            properties: Additional properties

        Returns:
            Created node data
        """
        query = """
        MERGE (a:Action {name: $name})
        SET a.category = $category,
            a.created = datetime()
        SET a += $properties
        RETURN a
        """
        params = {
            "name": action_name,
            "category": category,
            "properties": properties or {}
        }
        return self.execute_write(query, params)

    def create_policy(
        self,
        policy_id: str,
        policy_name: str,
        cloud_provider: str,
        vulnerable: bool,
        properties: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Create a Policy node.

        Args:
            policy_id: Unique policy identifier
            policy_name: Policy name
            cloud_provider: Cloud provider (AWS, Azure, GCP)
            vulnerable: Whether policy has vulnerabilities
            properties: Additional properties (document, ai_response, etc.)

        Returns:
            Created node data
        """
        query = """
        MERGE (p:Policy {id: $id})
        SET p.name = $name,
            p.provider = $provider,
            p.vulnerable = $vulnerable,
            p.created = datetime()
        SET p += $properties
        RETURN p
        """
        params = {
            "id": policy_id,
            "name": policy_name,
            "provider": cloud_provider,
            "vulnerable": vulnerable,
            "properties": properties or {}
        }
        return self.execute_write(query, params)

    def create_relationship(
        self,
        from_id: str,
        from_label: str,
        to_id: str,
        to_label: str,
        relationship_type: str,
        properties: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Create a relationship between two nodes.

        Args:
            from_id: Source node ID
            from_label: Source node label
            to_id: Target node ID
            to_label: Target node label
            relationship_type: Relationship type
            properties: Relationship properties

        Returns:
            Created relationship data
        """
        # Determine the ID property based on label
        from_id_prop = "arn" if from_label == "Resource" else "id" if from_label != "Action" else "name"
        to_id_prop = "arn" if to_label == "Resource" else "id" if to_label != "Action" else "name"

        query = f"""
        MATCH (a:{from_label} {{{from_id_prop}: $from_id}})
        MATCH (b:{to_label} {{{to_id_prop}: $to_id}})
        MERGE (a)-[r:{relationship_type}]->(b)
        SET r += $properties
        RETURN r
        """
        params = {
            "from_id": from_id,
            "to_id": to_id,
            "properties": properties or {}
        }
        return self.execute_write(query, params)

    def get_statistics(self) -> Dict[str, int]:
        """
        Get database statistics.

        Returns:
            Dictionary with node and relationship counts
        """
        stats_query = """
        MATCH (n)
        RETURN
            count(n) as total_nodes,
            count(CASE WHEN n:Principal THEN 1 END) as principals,
            count(CASE WHEN n:Resource THEN 1 END) as resources,
            count(CASE WHEN n:Action THEN 1 END) as actions,
            count(CASE WHEN n:Policy THEN 1 END) as policies
        """
        rel_query = "MATCH ()-[r]->() RETURN count(r) as relationships"

        node_stats = self.execute_query(stats_query)[0]
        rel_stats = self.execute_query(rel_query)[0]

        return {
            **node_stats,
            **rel_stats
        }


def create_neo4j_client_from_config(config: Dict[str, Any]) -> Optional[Neo4jClient]:
    """
    Create Neo4j client from configuration.

    Args:
        config: Configuration dictionary

    Returns:
        Neo4jClient instance or None if disabled
    """
    neo4j_config = config.get('neo4j', {})

    if not neo4j_config.get('enabled', False):
        return None

    # Get password from environment variable
    password_env = neo4j_config.get('password_env', 'NEO4J_PASSWORD')
    password = os.getenv(password_env)

    if not password:
        logging.warning(f"Neo4j password not found in environment variable {password_env}")
        return None

    try:
        client = Neo4jClient(
            uri=neo4j_config.get('uri', 'bolt://localhost:7687'),
            username=neo4j_config.get('username', 'neo4j'),
            password=password,
            database=neo4j_config.get('database', 'neo4j')
        )

        # Create constraints and indexes
        client.create_constraints()

        return client
    except Exception as e:
        logging.error(f"Failed to create Neo4j client: {str(e)}")
        return None
