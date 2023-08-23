content = request.form['content']
        data["content"] = content
        lowers = content.lower()



# API endpoint to edit a sentence post
@app.route('/sentence/<int:sentence_id>', methods=['POST'])
@jwt_required()
def edit_sentence(sentence_id):
    user_id = get_jwt_identity()

    cur = mysql.connection.cursor()
    cur.execute("SELECT * FROM sentences WHERE sentence_id = %s", (sentence_id,))
    sentence = cur.fetchone()

    if not sentence:
        return jsonify({'message': 'Sentence not found'}), 404

    if sentence[3] != user_id:
        return jsonify({'message': 'You do not have permission to edit this sentence'}), 403

    title = request.form.get('title')
    content = request.form.get('content')

    cur.execute("UPDATE sentences SET title = %s, content = %s WHERE sentence_id = %s",(title, content, sentence_id))
    mysql.connection.commit()
    cur.close()
    
    return redirect(url_for('manage_sentence', sentence_id=sentence_id))

    # return jsonify({'message': 'Sentence updated successfully'}), 200



# API endpoint to delete a sentence .
@app.route('/sentence/<int:sentence_id>', methods=['DELETE'])
#ensuring user must provide a valid JSON Web Token (JWT)
@jwt_required()
def delete_sentence(sentence_id):
    #retrieving  user_id from the current valid JWT
    user_id = get_jwt_identity()
#connection creation for interacting with data base
    cur = mysql.connection.cursor()
    #selecting all columns (*) from the 'sentences' table where the 'sentence_id
    cur.execute("SELECT * FROM sentences WHERE sentence_id = %s", (sentence_id,))
    sentence = cur.fetchone()

    if not sentence:
        return jsonify({'message': 'sentence not found'}), 404

    if sentence[3] != user_id:
        return jsonify({'message': 'You do not have permission to delete this sentence'}), 403
        #query to delete a row from the 'sentences' table where the 'sentence_id' column
    cur.execute("DELETE FROM sentences WHERE sentence_id = %s", (sentence_id,))
    mysql.connection.commit()
    cur.close()
 
    return jsonify({'message': 'sentence deleted successfully'}), 200

